use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::Address as AlloyAddress;
use base64::encode;
use hmac_sha256::HMAC;
use serde::{Deserialize, Serialize};

use kinode_process_lib::{http, vfs};
use kinode_process_lib::kernel_types::MessageType;
use kinode_process_lib::{
    await_message, call_init, get_blob, get_typed_state, println, set_state,
    Address, Message, LazyLoadBlob, ProcessId, Request, Response,
};

wit_bindgen::generate!({
    path: "wit",
    world: "process",
    exports: {
        world: Component,
    },
});

const DEFAULT_COMFYUI_HOST: &str = "10.3.104.223";
const DEFAULT_COMFYUI_PORT: u16 = 5000;
const DEFAULT_COMFYUI_CLIENT_ID: u32 = 0;

#[derive(Debug, Serialize, Deserialize)]
enum AdminRequest {
    SetRouterProcess { process_id: String },
    SetRollupSequencer { address: String },
    SetIsReady { is_ready: bool },
    SetComfyUi { host: String, port: u16, client_id: u32 },
    SetAzure { connect_string: String, container_name: String },
}

#[derive(Debug, Serialize, Deserialize)]
enum AdminResponse {
    SetRouterProcess { err: Option<String> },
    SetRollupSequencer { err: Option<String> },
    SetIsReady,
    SetComfyUi,
    SetAzure,
}

#[derive(Debug, Serialize, Deserialize)]
enum MemberRequest {
    SetIsReady { is_ready: bool },
    /// Router querying if member is ready to serve.
    QueryReady,
    ServeJob { job_id: u64, seed: u32, workflow: String, prompt: String },
}

#[derive(Debug, Serialize, Deserialize)]
enum MemberResponse {
    SetIsReady,
    /// Member Response to router: is_ready.
    QueryReady { is_ready: bool },
    /// Job result.
    /// Signature in body; result in LazyLoadBlob.
    ServeJob { job_id: u64, signature: Result<u64, String> },  // ?
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum SequencerRequest {
    Read(ReadRequest),
    //Write(SignedTransaction<OnChainDaoState>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum SequencerResponse {
    Read(ReadResponse),
    Write,  // TODO: return hash of tx?
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ReadRequest {
    All,
    Dao,
    Routers,
    Members,
    Proposals,
    Parameters,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ReadResponse {
    All(OnChainDaoState),
    Dao,
    Routers(Vec<String>),  // length 1 for now
    Members(Vec<String>),  // TODO: should probably be the HashMap
    Proposals,
    Parameters,
}

#[derive(Debug, Serialize, Deserialize)]
struct State {
    router_process: Option<ProcessId>,
    rollup_sequencer: Option<Address>,
    on_chain_state: OnChainDaoState,
    ws_channel_id: Option<u32>,
    comfyui_host: String,
    comfyui_port: u16,
    comfyui_client_id: u32,
    azure_connect_string: String,
    azure_container_name: String,
    is_ready: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct OnChainDaoState {
    pub routers: Vec<String>,  // length 1 for now
    pub members: HashMap<String, AlloyAddress>,
    pub proposals: HashMap<u64, ProposalInProgress>,
    // pub client_blacklist: Vec<String>,
    // pub member_blacklist: Vec<String>,
    pub queue_response_timeout_seconds: u8,
    pub serve_timeout_seconds: u16, // TODO
    pub max_outstanding_payments: u8,
    pub payment_period_hours: u8,
}

/// Possible proposals
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Proposal {
    ChangeRootNode(String),
    ChangeQueueResponseTimeoutSeconds(u8),
    ChangeMaxOutstandingPayments(u8),
    ChangePaymentPeriodHours(u8),
    Kick(String),
}

/// Possible proposals
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProposalInProgress {
    pub proposal: Proposal,
    pub votes: HashMap<String, SignedVote>,
}

/// A vote on a proposal
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Vote {
    pub proposal_hash: u64,
    pub is_yea: bool,
}

/// A signed vote on a proposal
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedVote {
    vote: Vote,
    signature: u64,
}

impl Default for State {
    fn default() -> Self {
        Self {
            router_process: None,
            rollup_sequencer: None,
            on_chain_state: OnChainDaoState::default(),
            ws_channel_id: None,
            comfyui_host: DEFAULT_COMFYUI_HOST.to_string(),
            comfyui_port: DEFAULT_COMFYUI_PORT,
            comfyui_client_id: DEFAULT_COMFYUI_CLIENT_ID,
            azure_connect_string: String::new(),
            azure_container_name: String::new(),
            is_ready: false,
        }
    }
}

impl Default for OnChainDaoState {
    fn default() -> Self {
        // TODO: get state from rollup
        Self {
            routers: vec![],
            members: HashMap::new(),
            proposals: HashMap::new(),
            queue_response_timeout_seconds: 0,
            serve_timeout_seconds: 0,
            max_outstanding_payments: 0,
            payment_period_hours: 0,
        }
    }
}

impl State {
    fn save(&self) -> anyhow::Result<()> {
        set_state(&serde_json::to_vec(self)?);
        Ok(())
    }

    fn load() -> Self {
        match get_typed_state(|bytes| Ok(serde_json::from_slice::<State>(bytes)?)) {
            Some(rs) => rs,
            None => State::default(),
        }
    }
}

// fn is_expected_channel_id(
//     state: &State,
//     channel_id: &u32,
// ) -> anyhow::Result<bool> {
//     let Some(ref current_channel_id) = state.ws_channel_id else {
//         return Err(anyhow::anyhow!("no ws channel set"));
//     };
//
//     Ok(channel_id == current_channel_id)
// }

fn parse_connection_string(connection_string: &str) -> (String, String) {
    let mut account_name = String::new();
    let mut account_key = String::new();

    for part in connection_string.split(';') {
        let mut parts = part.split('=');
        match parts.next() {
            Some("AccountName") => account_name = parts.next().unwrap_or_default().to_string(),
            Some("AccountKey") => account_key = parts.next().unwrap_or_default().to_string(),
            _ => {}
        }
    }

    (account_name, account_key)
}

fn send_to_azure(
    blob_name: &str,
    data: Vec<u8>,
    content_type: &str,
    state: &State,
) -> anyhow::Result<()> {
    let connect_string = &state.azure_connect_string;
    let container_name = &state.azure_container_name;

    let (storage_account, storage_key) = parse_connection_string(connect_string);

    let url = format!(
        "https://{}.blob.core.windows.net/{}/{}",
        storage_account, container_name, blob_name
    );
    let url = url::Url::parse(&url)?;

    let date = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let date_header = format!("{}", date);

    let string_to_sign = format!(
        "PUT\n\n\n{}\n\n{}\n\n\n\n\n\n\nx-ms-date:{}\nx-ms-version:2020-04-08\n/{}/{}\ncomp:block\nblockid:{}",
        data.len(),
        content_type,
        date_header,
        storage_account,
        container_name,
        encode("blockid")
    );

    let signature = encode(&HMAC::mac(string_to_sign.as_bytes(), &base64::decode(&storage_key)?));

    let authorization_header = format!("SharedKey {}:{}", storage_account, signature);

    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-ms-date".into(), date_header);
    headers.insert("x-ms-version".into(), "2020-04-08".into());
    headers.insert("Authorization".into(), authorization_header);
    headers.insert("CONTENT_TYPE".into(), content_type.into());
    headers.insert("CONTENT_LENGTH".into(), format!("{}", data.len()));

    let response = http::send_request_await_response(
        http::Method::PUT,
        url,
        Some(headers),
        5, // TODO
        data,
    )?;

    println!("Response: {:?}", response);

    Ok(())
}

fn serve_job(
    our: &Address,
    message: &Message,
    state: &mut State,
    workflows_dir: &str,
    images_dir: &str,
    job_id: u64,
    prompt: serde_json::Value,
) -> anyhow::Result<()> {
    state.is_ready = false;

    // connect to comfyui via WS
    let url = format!(
        "ws://{}:{}/ws?clientId={}",
        state.comfyui_host,
        state.comfyui_port,
        state.comfyui_client_id,
    );
    http::open_ws_connection(
        url,
        None,
        state.comfyui_client_id.clone(),
    )?;

    // queue prompt
    let url = format!("http://{}:{}/prompt", state.comfyui_host, state.comfyui_port);
    let url = url::Url::parse(&url)?;
    let prompt = serde_json::json!({"prompt": prompt, "client_id": state.comfyui_client_id});
    println!("{:?}", prompt);
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    let queue_response = http::send_request_await_response(
        http::Method::POST,
        url,
        Some(headers),
        //None,
        5,
        serde_json::to_vec(&prompt)?,
    )?;
    if !queue_response.status().is_success() {
        if let Ok(s) = String::from_utf8(queue_response.body().clone()) {
            return Err(anyhow::anyhow!("couldn't queue: {s}"));
        };
        return Err(anyhow::anyhow!("couldn't queue"));
    }
    let queue_response: serde_json::Value = serde_json::from_slice(&queue_response.body())?;
    let prompt_id = queue_response["prompt_id"].clone();

    // wait until done executing
    let mut qr_seen = false;
    loop {
        let message = await_message()?;
        let result = handle_message(&our, &message, state, workflows_dir, images_dir);
        if result.is_ok() {
            continue;
        }
        if !message.is_request() {
            continue;
        }
        let source = message.source();
        if source != &Address::new(our.node(), ("http_client", "distro", "sys")) {
            continue;
        }
        match serde_json::from_slice(message.body())? {
            http::HttpClientRequest::WebSocketPush { channel_id, message_type } => {
                if message_type == http::WsMessageType::Text {
                    let json: serde_json::Value = serde_json::from_slice(
                        &get_blob().unwrap().bytes
                    )?;
                    println!("{:?}", json);
                    if json["type"] == "executing" {
                        let data = json["data"].clone();
                        if data.get("node").is_none() && data["prompt_id"] == prompt_id {
                            println!("done!");
                            break;
                        }
                    }
                    if json["type"] == "status" {
                        if json["data"]["status"]["exec_info"]["queue_remaining"] == 0 {
                            if qr_seen {
                                println!("done");
                                break;
                            } else {
                                qr_seen = true;
                            }
                        }
                    }
                }
            }
            http::HttpClientRequest::WebSocketClose { channel_id } => {}
        }
    }

    // get images
    let serde_json::Value::String(prompt_id) = queue_response["prompt_id"].clone() else {
        panic!("");
    };
    let url = format!("http://{}:{}/history/{prompt_id}", state.comfyui_host, state.comfyui_port);
    let url = url::Url::parse(&url)?;
    let history_response = http::send_request_await_response(
        http::Method::GET,
        url,
        None,
        10,
        vec![],
    )?;
    if !history_response.status().is_success() {
        return Err(anyhow::anyhow!("couldn't fetch history"));
    }
    let history_response: serde_json::Value = serde_json::from_slice(&history_response.body())?;
    let serde_json::Value::Object(history_response) = history_response.clone() else {
    //let serde_json::Value::Object(history_response) = history_response["outputs"].clone() else {
        return Err(anyhow::anyhow!("/history response not a json object: {:?}", history_response));
    };
    let mut output_images = HashMap::new();

    for (k, v) in history_response.iter() {
        let serde_json::Value::Object(v) = v else {
            panic!("");
        };
        let v = v["outputs"].clone();
        let serde_json::Value::Object(v) = v else {
            panic!("");
        };
        for (node_id, node_output) in v.iter() {
        //for (node_id, node_output) in history_response.iter() {
            let Some(serde_json::Value::Array(images)) = node_output.get("images") else {
                continue;
            };
            let mut node_output_images = Vec::new();
            for image in images.iter() {
                let serde_json::Value::Object(image) = image else {
                    continue;
                };
                let json = serde_json::json!({
                    "filename": image["filename"],
                    "subfolder": image["subfolder"],
                    "type": image["type"],
                });
                let vars = serde_qs::to_string(&json)?;
                println!("{}\n{:?}", json, vars);
                let url = format!("http://{}:{}/view?{vars}", state.comfyui_host, state.comfyui_port);
                let Ok(url) = url::Url::parse(&url) else {
                    continue;
                };
                let view_response = http::send_request_await_response(
                    http::Method::GET,
                    url,
                    None,
                    5,
                    vec![],
                )?;
                if !view_response.status().is_success() {
                    println!("couldn't fetch view");
                    continue;
                }
                node_output_images.push(view_response.body().clone());
            }
            output_images.insert(node_id.clone(), node_output_images);
        }
    }

    // upload image(s)
    let image = output_images.values().next().unwrap()[0].clone();

    let image_id = uuid::Uuid::new_v4();
    let image_name = format!("{}.jpg", image_id);
    let content_type = "images/jpeg";  // TODO
    if !state.azure_connect_string.is_empty() && !state.azure_container_name.is_empty() {
        send_to_azure(&image_name, image, content_type, state)?;
    } else {
        let image_path = format!("{}/{}", images_dir, image_name);
        let file = vfs::open_file(&image_path, true, None)?;
        file.write(&image)?;
    }

    Ok(())
}

fn fetch_chain_state(state: &mut State) -> anyhow::Result<()> {
    let Some(rollup_sequencer) = state.rollup_sequencer.clone() else {
        return Err(anyhow::anyhow!("fetch_chain_state rollup_sequencer must be set before chain state can be fetched"));
    };
    Request::to(rollup_sequencer)  // TODO
        .body(vec![])
        .blob_bytes(serde_json::to_vec(&SequencerRequest::Read(ReadRequest::All))?)
        .expects_response(5) // TODO
        .send()?;
    Ok(())
}

fn await_chain_state(state: &mut State) -> anyhow::Result<()> {
    let Some(rollup_sequencer) = state.rollup_sequencer.clone() else {
        println!("err: {:?}", state);
        return Err(anyhow::anyhow!("fetch_chain_state rollup_sequencer must be set before chain state can be fetched"));
    };
    Request::to(rollup_sequencer)  // TODO
        .body(vec![])
        .blob_bytes(serde_json::to_vec(&SequencerRequest::Read(ReadRequest::All))?)
        .send_and_await_response(5)??;
    let Some(LazyLoadBlob { ref bytes, .. }) = get_blob() else {
        println!("err: no blob");
        return Err(anyhow::anyhow!("fetch_chain_state didn't get back blob"));
    };
    let Ok(SequencerResponse::Read(ReadResponse::All(new_dao_state))) = serde_json::from_slice(bytes) else {
        println!("err: {:?}", serde_json::from_slice::<serde_json::Value>(bytes));
        return Err(anyhow::anyhow!("fetch_chain_state got wrong Response back"));
    };
    state.on_chain_state = new_dao_state.clone();
    Ok(())
}

fn handle_admin_request(
    our: &Address,
    message: &Message,
    state: &mut State,
) -> anyhow::Result<()> {
    let source = message.source();
    if source.node() != our.node() {
        return Err(anyhow::anyhow!("only our can make AdminRequests; rejecting from {source:?}"));
    }
    match serde_json::from_slice(message.body())? {
        AdminRequest::SetRouterProcess { process_id } => {
            let process_id = process_id.parse()?;
            state.router_process = Some(process_id);
            Response::new()
                .body(serde_json::to_vec(&AdminResponse::SetRouterProcess { err: None })?)
                .send()?;
        }
        AdminRequest::SetRollupSequencer { address } => {
            let address = address.parse()?;
            state.rollup_sequencer = Some(address);
            await_chain_state(state)?;
            Response::new()
                .body(serde_json::to_vec(&AdminResponse::SetRollupSequencer { err: None })?)
                .send()?;
        }
        AdminRequest::SetIsReady { is_ready } => {
            state.is_ready = is_ready;
            let address = Address::new(
                state.on_chain_state.routers[0].clone(),
                state.router_process.clone().unwrap(),
            );
            Request::to(address)
                .body(serde_json::to_vec(&MemberRequest::SetIsReady { is_ready })?)
                .send()?;
            Response::new()
                .body(serde_json::to_vec(&AdminResponse::SetIsReady)?)
                .send()?;
        }
        AdminRequest::SetComfyUi { host, port, client_id } => {
            state.comfyui_host = host;
            state.comfyui_port = port;
            state.comfyui_client_id = client_id;
            Response::new()
                .body(serde_json::to_vec(&AdminResponse::SetComfyUi)?)
                .send()?;
        }
        AdminRequest::SetAzure { connect_string, container_name } => {
            state.azure_connect_string = connect_string;
            state.azure_container_name = container_name;
            Response::new()
                .body(serde_json::to_vec(&AdminResponse::SetAzure)?)
                .send()?;
        }
    }
    Ok(())
}

fn handle_member_request(
    our: &Address,
    message: &Message,
    state: &mut State,
    workflows_dir: &str,
    images_dir: &str,
) -> anyhow::Result<()> {
    let source = message.source();
    if !state.on_chain_state.routers.contains(&source.node().to_string()) {
        return Err(anyhow::anyhow!(
            "only routers can send member Requests; rejecting from {source:?}\n{state:?}"
        ));
    }
    let is_ready = state.is_ready.clone();
    match serde_json::from_slice(message.body())? {
        MemberRequest::QueryReady => {
            Response::new()
                .body(serde_json::to_vec(&MemberResponse::QueryReady { is_ready })?)
                .send()?;
        }
        MemberRequest::ServeJob { job_id, seed, workflow, prompt } => {
            if !is_ready {
                Response::new()
                    .body(serde_json::to_vec(&MemberResponse::ServeJob {
                        job_id,
                        signature: Err("not serving job: not ready".into()),
                    })?)
                    .send()?;
                return Err(anyhow::anyhow!("not serving job: not ready"));
            }
            let workflow = format!("{workflows_dir}/{workflow}.json");
            let workflow = vfs::open_file(&workflow, false, None)?
                .read()?;
            let workflow: serde_json::Value = serde_json::from_slice(&workflow)?;
            let serde_json::Value::String(pre_prompt) = workflow["prompts"]["pre_prompt"].clone() else {
                panic!("");
            };
            let serde_json::Value::String(post_prompt) = workflow["prompts"]["post_prompt"].clone() else {
                panic!("");
            };
            let positive_prompt = serde_json::json!(format!("{pre_prompt} {prompt} {post_prompt}"));
            let negative_prompt = workflow["prompts"]["negative_prompt"].clone();
            let serde_json::Value::String(positive_node) = workflow["prompts"]["prompt_node"].clone() else {
                panic!("");
            };
            let serde_json::Value::String(negative_node) = workflow["prompts"]["negative_node"].clone() else {
                panic!("");
            };
            let serde_json::Value::String(seed_node) = workflow["prompts"]["seed_node"].clone() else {
                panic!("");
            };
            //let positive_node = workflow["prompts"]["prompt_node"].to_string();
            //let negative_node = workflow["prompts"]["negative_node"].to_string();
            //let seed_node = workflow["prompts"]["seed_node"].to_string();
            //println!("{}", seed_node);
            //println!("{:?}", workflow);
            //let mut full_seed_node = workflow["workflow"][seed_node.clone()].clone();
            //println!("{}", full_seed_node);
            //full_seed_node["inputs"]["seed"] = seed.clone().into();
            //println!("{}", full_seed_node);
            let mut prompt = workflow["workflow"].clone();
            prompt[positive_node]["inputs"]["text"] = positive_prompt;
            prompt[negative_node]["inputs"]["text"] = negative_prompt;
            //prompt[seed_node] = full_seed_node.clone();
            prompt[seed_node]["inputs"]["seed"] = seed.into();
            serve_job(our, message, state, workflows_dir, images_dir, job_id, prompt)?;
        }
        MemberRequest::SetIsReady { .. } => {
            return Err(anyhow::anyhow!("unexpected MemberRequest"));
        }
    }
    Ok(())
}


fn handle_member_response(
    our: &Address,
    message: &Message,
    state: &mut State,
) -> anyhow::Result<()> {
    match serde_json::from_slice(message.body())? {
        MemberResponse::SetIsReady | MemberResponse::QueryReady { .. } => {}
        MemberResponse::ServeJob { job_id, signature } => {
            return Err(anyhow::anyhow!("unexpected MemberResponse"));
        }
    }
    Ok(())
}

fn handle_sequencer_response(state: &mut State) -> anyhow::Result<()> {
    let Some(LazyLoadBlob { ref bytes, .. }) = get_blob() else {
        return Err(anyhow::anyhow!("fetch_chain_state didn't get back blob"));
    };
    let Ok(SequencerResponse::Read(ReadResponse::All(new_dao_state))) = serde_json::from_slice(bytes) else {
        return Err(anyhow::anyhow!("fetch_chain_state got wrong Response back"));
    };
    state.on_chain_state = new_dao_state.clone();
    Ok(())
}

fn handle_message(
    our: &Address,
    message: &Message,
    state: &mut State,
    workflows_dir: &str,
    images_dir: &str,
) -> anyhow::Result<()> {
    if message.is_request() {
        if handle_admin_request(our, &message, state).is_ok() {
            return Ok(());
        }
        if state.router_process.is_none() {
            return Err(anyhow::anyhow!(
                "provider package must be set by AdminRequest before accepting other Requests"
            ));
        }
        return handle_member_request(our, &message, state, workflows_dir, images_dir);
    }

    if handle_sequencer_response(state).is_ok() {
        return Ok(());
    };
    handle_member_response(our, &message, state)?;

    Ok(())
}

call_init!(init);
fn init(our: Address) {
    println!("{our}: begin");

    let _ = http::close_ws_connection(DEFAULT_COMFYUI_CLIENT_ID);

    let workflows_dir = vfs::create_drive(our.package_id(), "workflows", None).unwrap();
    let images_dir = vfs::create_drive(our.package_id(), "images", None).unwrap();
    let mut state = State::default();

    loop {
        let message = await_message();
        let Ok(message) = message else {
            println!("{}: error: {:?}", our.process(), message);
            continue;
        };
        match handle_message(&our, &message, &mut state, &workflows_dir, &images_dir) {
            Ok(()) => {}
            Err(e) => {
                println!("{}: error: {:?}", our.process(), e);
            }
        };
    }
}

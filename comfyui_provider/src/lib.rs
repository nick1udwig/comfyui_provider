use std::collections::HashMap;
use std::str::FromStr;

use alloy_primitives::Address as AlloyAddress;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use kinode_process_lib::{http, vfs};
use kinode_process_lib::{
    await_message, call_init, get_blob, get_typed_state, println, set_state,
    Address, Message, LazyLoadBlob, ProcessId, Request, Response,
};

wit_bindgen::generate!({
    path: "wit",
    world: "process",
});

const DEFAULT_COMFYUI_HOST: &str = "localhost";
const DEFAULT_COMFYUI_PORT: u16 = 8188;
const DEFAULT_COMFYUI_CLIENT_ID: u32 = 0;

#[derive(Debug, Serialize, Deserialize)]
enum AdminRequest {
    SetRouterProcess { process_id: String },
    SetRollupSequencer { address: String },
    SetIsReady { is_ready: bool },
    SetComfyUi { host: String, port: u16, client_id: u32 },
}

#[derive(Debug, Serialize, Deserialize)]
enum AdminResponse {
    SetRouterProcess { err: Option<String> },
    SetRollupSequencer { err: Option<String> },
    SetIsReady,
    SetComfyUi,
}

#[derive(Debug, Serialize, Deserialize)]
enum MemberRequest {
    SetIsReady { is_ready: bool },
    /// Router querying if member is ready to serve.
    QueryReady,
    JobTaken { job_id: u64 },
    ServeJob { job_id: u64, seed: u32, workflow: String, parameters: String },
    ///// Job result.
    ///// Signature in body; result in LazyLoadBlob.
    JobUpdate { job_id: u64, is_final: bool, signature: Result<u64, String> },
}

#[derive(Debug, Serialize, Deserialize)]
enum MemberResponse {
    SetIsReady,
    /// Member Response to router: is_ready.
    QueryReady { is_ready: bool },
    /// Ack
    JobTaken,
    //ServeJob { job_id: u64, signature: Result<u64, String> },  // ?
    /// Ack
    ServeJob,
    /// Ack
    JobUpdate,
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
    comfyui_host: String,
    comfyui_port: u16,
    comfyui_client_id: u32,
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
            comfyui_host: DEFAULT_COMFYUI_HOST.to_string(),
            comfyui_port: DEFAULT_COMFYUI_PORT,
            comfyui_client_id: DEFAULT_COMFYUI_CLIENT_ID,
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

#[derive(Error, Debug)]
enum NotAMatchError {
    #[error("Match failed")]
    NotAMatch,
}

#[derive(Error, Debug)]
enum ExtraWsMessageError {
    #[error("Extra WS message after close")]
    ExtraWsMessage,
}

#[derive(Serialize, Deserialize, Debug)]
struct ComfyUpdate {
    #[serde(rename = "type")]
    type_: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ComfyUpdateExecuting {
    data: ComfyUpdateExecutingData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ComfyUpdateExecutingData {
    prompt_id: Option<String>,
    node: Option<String>,
    output: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Workflow {
    pub name: String,
    pub description: String,
    pub config: Config,
    pub nodes_config: NodesConfig,
    //pub prompts: Prompts,
    pub nodes: Nodes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub aspect_ratio: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NodesConfig {
    pub prompt_node: String,
    pub negative_node: String,
    pub seed_node: String,
    pub websocket_node: String,
    pub sampler_node: String,
    pub latent_image_node: String,
    pub checkpoint_node: String,
    pub cfg_scale_node: String,
    pub character_node: String,
    pub detailer_node: String,
    pub styler_node: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Prompts {
    pub pre_prompt: String,
    pub prompt_must_include: String,
    pub post_prompt: String,
    pub negative_prompt: String,
}

type Nodes = HashMap<String, Node>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Node {
    pub inputs: HashMap<String, serde_json::Value>,
    pub class_type: String,
    pub _meta: Meta,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Meta {
    pub title: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct GenerateImageRequest {
    pub quality: GenerationQuality,
    pub aspect_ratio: AspectRatios,
    pub workflow: String,
    pub user_id: String,
    pub negative_prompt: String,
    pub positive_prompt: String,
    pub cfg_scale: serde_json::Value,
    pub character: GenerateImageRequestCharacter,
    pub styler: GenerateImageRequestStyler,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct GenerateImageRequestCharacter {
    pub id: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct GenerateImageRequestStyler {
    pub id: String,
}

// Define a struct to hold dimensions.
#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Dimension {
    width: u32,
    height: u32,
}

// Define the type alias for nested HashMaps.
type DimensionMap = HashMap<GenerationQuality, HashMap<AspectRatios, Dimension>>;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Hash, Eq)]
pub enum GenerationQuality {
    #[serde(rename = "fast")]
    Fast,
    #[serde(rename = "quality")]
    Quality,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Hash, Eq)]
pub enum AspectRatios {
    #[serde(rename = "square")]
    Square,
    #[serde(rename = "portrait")]
    Portrait,
    #[serde(rename = "landscape")]
    Landscape,
}

#[derive(Debug, Serialize, Deserialize)]
struct ModelDetails {
    lora_name: String,
    strength_model: HashMap<String, f64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Character {
    id: String,
    name: String,
    model: ModelDetails,
    //image: String,
    prompt: String,
    negative_prompt: String,
    trigger_words: Vec<String>,
}

type Characters = Vec<Character>;

#[derive(Debug, Serialize, Deserialize)]
struct Styler {
    id: String,
    name: String,
    checkpoint: String,
    model: ModelDetails,
    sampler_name: String,
    scheduler: String,
    prompt: String,
    negative_prompt: String,
    cfg_scale: CfgScale,
    steps: StepDetails,
    detailer: Detailer,
    // Include this field if necessary as seen in some JSON entries
    character_model: Option<HashMap<String, serde_json::Value>>,
}

type Stylers = Vec<Styler>;

#[derive(Debug, Serialize, Deserialize)]
struct CfgScale {
    min: f64,
    max: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct StepDetails {
    min: i32,
    max: i32,
    quality_map: HashMap<String, f64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Detailer {
    more_details: f64,
}

fn resolve_dimensions(q: &GenerationQuality, r: &AspectRatios, data_dir: &str) -> anyhow::Result<(u32, u32)> {
    let quality = format!("{data_dir}/quality.json");
    let quality = vfs::open_file(&quality, false, None)?
        .read()?;
    let quality: DimensionMap = serde_json::from_slice(&quality)?;
    let dimensions = quality
        .get(q)
        .and_then(|m| m.get(r))
        .ok_or_else(|| anyhow::anyhow!(""))?;
    Ok((dimensions.width, dimensions.height))
}

fn get_character(character_id: &str, data_dir: &str) -> anyhow::Result<Character> {
    let characters = format!("{data_dir}/characters.json");
    let characters = vfs::open_file(&characters, false, None)?
        .read()?;
    let characters: Characters = serde_json::from_slice(&characters)?;
    for character in characters {
        if character.id != character_id {
            continue;
        }
        return Ok(character)
    }
    return Err(anyhow::anyhow!("didn't find character with id {character_id}"))
}

fn get_styler(styler_id: &str, data_dir: &str) -> anyhow::Result<Styler> {
    let stylers = format!("{data_dir}/stylers.json");
    let stylers = vfs::open_file(&stylers, false, None)?
        .read()?;
    let stylers: Stylers = serde_json::from_slice(&stylers)?;
    for styler in stylers {
        if styler.id != styler_id {
            continue;
        }
        return Ok(styler)
    }
    return Err(anyhow::anyhow!("didn't find styler with id {styler_id}"))
}

/// Business logic specific to the task & workflow served by this provider.
fn build_nodes(
    workflow_config: Workflow,
    parameters: &str,
    data_dir: &str,
    seed: &u32,
) -> anyhow::Result<Nodes> {
    let req: GenerateImageRequest = serde_json::from_str(&parameters)?;
    let mut nodes = workflow_config.nodes;

    let (width, height) = resolve_dimensions(&req.quality, &req.aspect_ratio, data_dir)?;
    let client_id: String = req.user_id.replace("user:", "").replace("_", "-");

    // character setup
    let character_config = get_character(&req.character.id, data_dir)?;
    //let Ok(character_config) = db::character_by_id(&req.character.id).await else {
    //    return Err(()); //HttpResponse::BadRequest().finish();
    //};
    let lora_name = character_config.model.lora_name;
    let strength = character_config.model.strength_model.get("1024").unwrap();
    let mut character_node = nodes
        .get(&workflow_config.nodes_config.character_node)
        .unwrap()
        .clone();
    character_node.inputs.insert("lora_name".into(), serde_json::json!(lora_name));
    character_node
        .inputs
        .insert("strength_model".into(), serde_json::json!(strength));
    nodes.insert(
        workflow_config.nodes_config.character_node.clone(),
        character_node.clone(),
    );

    // styler setup
    let styler_config = get_styler(&req.styler.id, data_dir)?;
    //let Ok(styler_config) = db::styler_by_id(&req.styler.id).await else {
    //    return Err(()); //HttpResponse::BadRequest().finish();
    //};
    let lora_name = styler_config.model.lora_name;
    let strength = styler_config.model.strength_model.get("1024").unwrap();
    let mut styler_node = nodes
        .get(&workflow_config.nodes_config.styler_node)
        .unwrap()
        .clone();
    styler_node.inputs.insert("lora_name".into(), serde_json::json!(lora_name));
    styler_node
        .inputs
        .insert("strength_model".into(), serde_json::json!(strength));
    nodes.insert(
        workflow_config.nodes_config.styler_node,
        styler_node.clone(),
    );
    // step count based on quality
    let mut sampler_node = nodes
        .get(&workflow_config.nodes_config.sampler_node)
        .unwrap()
        .clone();
    sampler_node.inputs.insert(
        "steps".into(),
        serde_json::json!(styler_config.steps.quality_map.get("1024").unwrap()),
    );
    nodes.insert(
        workflow_config.nodes_config.sampler_node,
        sampler_node.clone(),
    );
    // if style has a strength override for a character, apply it
    if let Some(char_model) = styler_config.character_model {
        if let Some(character) = char_model.get(&req.character.id) {
            character_node
                .inputs
                .insert("strength_model".into(), character.clone());
            nodes.insert(
                workflow_config.nodes_config.character_node,
                character_node,
            );
        }
    }

    // user prompt setup
    let positive_prompt = format!(
        "{}, {}, {}",
        styler_config.prompt,
        character_config.prompt,
        req.positive_prompt,
    );
    let negative_prompt = format!(
        "{}, {}, nsfw",
        styler_config.negative_prompt,
        req.negative_prompt,
    );
    let positive_node_name = workflow_config.nodes_config.prompt_node;
    let negative_node_name = workflow_config.nodes_config.negative_node;
    let mut pos_node = nodes.get(&positive_node_name).unwrap().clone();
    pos_node.inputs.insert(
        "text".into(),
        serde_json::to_value(positive_prompt.clone()).unwrap(),
    );
    nodes.insert(positive_node_name, pos_node);
    let mut neg_node = nodes.get(&negative_node_name).unwrap().clone();
    neg_node.inputs.insert(
        "text".into(),
        serde_json::to_value(negative_prompt.clone()).unwrap(),
    );
    nodes.insert(negative_node_name, neg_node);

    //// store historical prompt
    //let hp = HistoricalPrompt::new(
    //    req.workflow.clone(),
    //    positive_prompt,
    //    negative_prompt,
    //    req.user_id.clone(),
    //);
    //let Ok(_) = db::save_historical_prompt(&hp).await else {
    //    return Err(()); //HttpResponse::UnprocessableEntity().finish();
    //};

    // seed setup
    let seed_node_id = workflow_config.nodes_config.seed_node;
    let mut seed_node = nodes.get(&seed_node_id.clone()).unwrap().clone();
    seed_node
        .inputs
        .insert("seed".into(), serde_json::to_value(seed).unwrap());
    nodes.insert(seed_node_id.clone(), seed_node);

    let mut user_config = serde_json::to_value(req.clone()).unwrap();
    if let Some(obj) = user_config.as_object_mut() {
        obj.insert("seed".to_string(), serde_json::to_value(seed).unwrap());
    }

    // cfg scale setup
    let cfg_scale_node_name = workflow_config.nodes_config.cfg_scale_node;
    let mut cfg_node = nodes.get(&cfg_scale_node_name).unwrap().clone();
    cfg_node
        .inputs
        .insert("cfg_scale".into(), req.cfg_scale.clone());
    nodes.insert(cfg_scale_node_name, cfg_node);

    // aspect ratio setup
    let latent_image_node_name = workflow_config.nodes_config.latent_image_node;
    let mut latent_image_node = nodes.get(&latent_image_node_name).unwrap().clone();
    latent_image_node
        .inputs
        .insert("width".into(), serde_json::to_value(width).unwrap());
    latent_image_node
        .inputs
        .insert("height".into(), serde_json::to_value(height).unwrap());
    nodes.insert(latent_image_node_name, latent_image_node);

    Ok(nodes)
}

fn serve_job(
    our: &Address,
    _message: &Message,
    state: &mut State,
    workflows_dir: &str,
    data_dir: &str,
    images_dir: &str,
    job_id: u64,
    nodes: HashMap<String, Node>,
    image_done_node_id: &str,
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
    let prompt = serde_json::json!({
        "prompt": nodes,
        "client_id": format!("{}", state.comfyui_client_id),
    });
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    let queue_response = http::send_request_await_response(
        http::Method::POST,
        url,
        Some(headers),
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
    let serde_json::Value::String(prompt_id) = queue_response["prompt_id"].clone() else {
        panic!("");
    };

    let address = Address::new(
        state.on_chain_state.routers[0].clone(),
        state.router_process.clone().unwrap(),
    );
    let mut current_node = String::new();
    loop {
        let message = await_message()?;
        let result = handle_message(&our, &message, state, workflows_dir, data_dir, images_dir);
        let source = message.source();
        if result.is_ok()
        || !message.is_request()
        || source != &Address::new(our.node(), ("http_client", "distro", "sys")) {
            continue;
        }
        match serde_json::from_slice(message.body())? {
            http::HttpClientRequest::WebSocketPush { channel_id, message_type } => {
                if message_type == http::WsMessageType::Text {
                    let blob_bytes = &get_blob().unwrap().bytes;
                    let update: ComfyUpdate = serde_json::from_slice(&blob_bytes)?;
                    //println!("text: {:?}", serde_json::from_slice::<serde_json::Value>(&blob_bytes));
                    if update.type_ == "executing" {
                        let update: ComfyUpdateExecuting = serde_json::from_slice(&blob_bytes)?;
                        if update.data.prompt_id.unwrap_or("".into()) == prompt_id {
                            if update.data.node.is_none() {
                                break;
                            } else {
                                //println!("current_node: {:?}", update.data.node);
                                current_node = update.data.node.unwrap();
                            }
                        }
                    } else if update.type_ == "status" {
                    }
                } else if message_type == http::WsMessageType::Binary {
                    // TODO: inherit instead? Then client will need to strip header
                    let is_final = current_node == image_done_node_id;
                    let signature = Ok(0);  // TODO
                    let blob_bytes = &get_blob().unwrap().bytes;
                    Request::to(address.clone())
                        .body(serde_json::to_vec(&MemberRequest::JobUpdate { job_id, is_final, signature })?)
                        .blob_bytes(blob_bytes[8..].to_vec())
                        .send()?;
                    if is_final {
                        break;
                    }
                }
            }
            http::HttpClientRequest::WebSocketClose { channel_id } => {
                //println!("got ws close");
            }
        }
    }

    http::close_ws_connection(state.comfyui_client_id.clone())?;

    Request::to(address)
        .body(serde_json::to_vec(&MemberRequest::SetIsReady { is_ready: true })?)
        .send()?;
    state.is_ready = true;
    state.save()?;

    Ok(())
}

// fn fetch_chain_state(state: &mut State) -> anyhow::Result<()> {
//     let Some(rollup_sequencer) = state.rollup_sequencer.clone() else {
//         return Err(anyhow::anyhow!("fetch_chain_state rollup_sequencer must be set before chain state can be fetched"));
//     };
//     Request::to(rollup_sequencer)  // TODO
//         .body(vec![])
//         .blob_bytes(serde_json::to_vec(&SequencerRequest::Read(ReadRequest::All))?)
//         .expects_response(5) // TODO
//         .send()?;
//     Ok(())
// }

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
        if serde_json::from_slice::<AdminRequest>(message.body()).is_err() {
            return Err(NotAMatchError::NotAMatch.into());
        }
        return Err(anyhow::anyhow!("only our can make AdminRequests; rejecting from {source:?}"));
    }
    match serde_json::from_slice(message.body()) {
        Ok(AdminRequest::SetRouterProcess { process_id }) => {
            let process_id = process_id.parse()?;
            state.router_process = Some(process_id);
            Response::new()
                .body(serde_json::to_vec(&AdminResponse::SetRouterProcess { err: None })?)
                .send()?;
        }
        Ok(AdminRequest::SetRollupSequencer { address }) => {
            let address = address.parse()?;
            state.rollup_sequencer = Some(address);
            await_chain_state(state)?;
            Response::new()
                .body(serde_json::to_vec(&AdminResponse::SetRollupSequencer { err: None })?)
                .send()?;
        }
        Ok(AdminRequest::SetIsReady { is_ready }) => {
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
        Ok(AdminRequest::SetComfyUi { host, port, client_id }) => {
            state.comfyui_host = host;
            state.comfyui_port = port;
            state.comfyui_client_id = client_id;
            Response::new()
                .body(serde_json::to_vec(&AdminResponse::SetComfyUi)?)
                .send()?;
        }
        Err(_e) => {
            return Err(NotAMatchError::NotAMatch.into());
        }
    }
    state.save()?;
    Ok(())
}

fn handle_member_request(
    our: &Address,
    message: &Message,
    state: &mut State,
    workflows_dir: &str,
    data_dir: &str,
    images_dir: &str,
) -> anyhow::Result<()> {
    let source = message.source();
    if !state.on_chain_state.routers.contains(&source.node().to_string()) {
        if source.node() == our.node() {
            // handle extra WS messages: Close & queued up before close finished
            if let Ok(_req) = serde_json::from_slice::<http::HttpClientRequest>(message.body()) {
                return Err(ExtraWsMessageError::ExtraWsMessage.into());
            }
        }
        return Err(anyhow::anyhow!(
            "only routers can send member Requests; rejecting from {source:?}\n{:?}",
            serde_json::from_slice::<serde_json::Value>(message.body()),
        ));
    }
    let is_ready = state.is_ready.clone();
    match serde_json::from_slice(message.body()) {
        Ok(MemberRequest::QueryReady) => {
            Response::new()
                .body(serde_json::to_vec(&MemberResponse::QueryReady { is_ready })?)
                .send()?;
        }
        Ok(MemberRequest::JobTaken { .. }) => {
            // Ack
            Response::new()
                .body(serde_json::to_vec(&MemberResponse::JobTaken)?)
                .send()?;
        }
        Ok(MemberRequest::ServeJob { job_id, ref seed, ref workflow, ref parameters }) => {
            Response::new() // TODO
                .body(serde_json::to_vec(&MemberResponse::ServeJob)?)
                .send()?;
            if !is_ready {
                return Err(anyhow::anyhow!("not serving job: not ready"));
            }
            let workflow = format!("{workflows_dir}/{workflow}.json");
            let base_workflow = vfs::open_file(&workflow, false, None)?
                .read()?;
            let base_workflow: Workflow = serde_json::from_slice(&base_workflow)?;
            let image_done_node_id = base_workflow.nodes_config.websocket_node.clone();
            let nodes = build_nodes(base_workflow, parameters, data_dir, seed)?;
            state.comfyui_client_id = seed.clone();  // TODO
            serve_job(
                our,
                message,
                state,
                workflows_dir,
                data_dir,
                images_dir,
                job_id,
                nodes,
                &image_done_node_id,
            )?;
        }
        Ok(MemberRequest::SetIsReady { .. }) | Ok(MemberRequest::JobUpdate { .. }) => {
            return Err(anyhow::anyhow!("unexpected MemberRequest"));
        }
        Err(_e) => {
            return Err(NotAMatchError::NotAMatch.into());
        }
    }
    Ok(())
}


fn handle_member_response(
    message: &Message,
) -> anyhow::Result<()> {
    match serde_json::from_slice(message.body()) {
        Ok(MemberResponse::SetIsReady) | Ok(MemberResponse::QueryReady { .. }) | Ok(MemberResponse::JobUpdate) => {}
        Ok(MemberResponse::ServeJob { .. }) | Ok(MemberResponse::JobTaken) => {
            return Err(anyhow::anyhow!("unexpected MemberResponse"));
        }
        Err(_e) => {
            return Err(NotAMatchError::NotAMatch.into());
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
    state.save()?;
    Ok(())
}

fn handle_message(
    our: &Address,
    message: &Message,
    state: &mut State,
    workflows_dir: &str,
    data_dir: &str,
    images_dir: &str,
) -> anyhow::Result<()> {
    if message.is_request() {
        match handle_admin_request(our, message, state) {
            Ok(_) => return Ok(()),
            Err(e) => {
                if e.downcast_ref::<NotAMatchError>().is_none() {
                    return Err(e);
                }
            }
        }
        return handle_member_request(our, message, state, workflows_dir, data_dir, images_dir);
    }

    if handle_sequencer_response(state).is_ok() {
        return Ok(());
    };
    handle_member_response(&message)?;

    Ok(())
}

call_init!(init);
fn init(our: Address) {
    println!("{}: begin", our.process());

    let workflows_dir = vfs::create_drive(our.package_id(), "workflows", None).unwrap();
    let data_dir = vfs::create_drive(our.package_id(), "data", None).unwrap();
    let images_dir = vfs::create_drive(our.package_id(), "images", None).unwrap();
    let mut state = State::load();

    loop {
        let message = await_message();
        let Ok(message) = message else {
            println!("{}: error: {:?}", our.process(), message);
            continue;
        };
        match handle_message(
            &our,
            &message,
            &mut state,
            &workflows_dir,
            &data_dir,
            &images_dir,
        ) {
            Ok(()) => {}
            Err(e) => {
                // handle extra WS messages: Close & queued up before close finished
                if e.downcast_ref::<ExtraWsMessageError>().is_none() {
                    println!("{}: error: {:?}", our.process(), e);
                }
            }
        };
    }
}

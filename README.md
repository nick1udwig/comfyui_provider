# comfyui_provider

A provider for use with

https://github.com/nick1udwig/provider-dao-rollup

https://github.com/nick1udwig/provider_dao_router

https://github.com/comfyanonymous/ComfyUI

## Setup

```
# Spin up node to run rollup
# Spin up a node to run router (rollup & router could be run on same node)
# Spin up node(s) to run providers

# Say the rollup node is `ROLLUP.os`,     running at ROLLUP_PORT
#     the router node is `ROUTER.os`,     running at ROUTER_PORT
#     the provider node is `PROVIDER.os`, running at PROVIDER_PORT, with home directory at PROVIDER_HOME
# Say ComfyUI is running on server foobar.com port 9999

# Install rollup (bash)
git clone https://github.com/nick1udwig/provider-dao-rollup
kit bs provider-dao-rollup/sequencer -p $ROLLUP_PORT

# Install router (bash)
git clone https://github.com/nick1udwig/provider_dao_router
kit bs provider_dao_router -p $ROUTER_PORT

# Install provider (bash)
git clone https://github.com/nick1udwig/comfyui_provider
kit bs comfyui_provider -p $PROVIDER_PORT
mkdir -p vfs/comfyui_provider\:nick1udwig.os/workflows/
cp comfyui_provider/workflow.json ${PROVIDER_HOME}/vfs/comfyui_provider\:nick1udwig.os/workflows/
cp -r data ${PROVIDER_HOME}/vfs/comfyui_provider\:nick1udwig.os/

# Setup rollup (rollup.os terminal)
admin:provider-dao-rollup:nick1udwig.os {"SetRouters": ["ROUTER.os"]}
admin:provider-dao-rollup:nick1udwig.os {"SetMembers": ["PROVIDER.os"]}

# Setup router (router.os terminal)
admin:provider_dao_router:nick1udwig.os {"SetProviderProcess": {"process_id": "comfyui_provider:comfyui_provider:nick1udwig.os"}}
admin:provider_dao_router:nick1udwig.os {"SetRollupSequencer": {"address": "ROLLUP.os@sequencer:provider-dao-rollup:nick1udwig.os"}}

# Setup provider (provider.os terminal)
admin:comfyui_provider:nick1udwig.os {"SetRouterProcess": {"process_id": "provider_dao_router:provider_dao_router:nick1udwig.os"}}
admin:comfyui_provider:nick1udwig.os {"SetRollupSequencer": {"address": "ROLLUP.os@sequencer:provider-dao-rollup:nick1udwig.os"}}
admin:comfyui_provider:nick1udwig.os {"SetIsReady": {"is_ready": true}}
admin:comfyui_provider:nick1udwig.os {"SetComfyUi": {"host": "foobar.com", "port": 9999, "client_id": 0}}
```

## Example usage

See https://github.com/nick1udwig/comfyui_client?tab=readme-ov-file#example-usage

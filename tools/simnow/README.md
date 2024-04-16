# How to start simnow endpoint mode using scripts
```
Simnow Endpoints Mode Test Flow:
  https://confluence.amd.com/pages/viewpage.action?spaceKey=AIE&title=SimNow+Endpoint+Test+Flow

Steps:
  1. customize your config json file
    - If you are in AMD network, please customize "build_amd_env.json"
      Note: the CONF_INSTALL_ART is a local storage, you need to entire dir from
            /public/bugcases/CR/1147000-1147999/1147090/art

      "CONF_INSTALL_ART" : "/local_vol2_nobackup/user/nicgoote/MPAIE/EndpointScript/art"
      "CONF_INSTALL_HOST_IP" : "192.168.122.76",
      "CONF_INSTALL_AMDAIE" : "/local_vol2_nobackup/user/nicgoote/MPAIE/EndpointScript/amd-aie",
      "CONF_INSTALL_DIR" : "/local_vol2_nobackup/user/nicgoote/MPAIE/EndpointScript/installdir"

    - IF you are in Xilinx network, please customize "build_xlnx_env.json"
      "CONF_INSTALL_HOST_IP" : "192.168.122.76",
      "CONF_INSTALL_AMDAIE" : "/proj/rdi/staff/davidzha/amd-aie",
      "CONF_INSTALL_DIR" : "/scratch/davidz"

  2. run simnow, qemu and vf driver from 3 different terminals
    - If you are in AMD netowrk
      in terminal 1: ./build_ci.sh --simnow --config build_amd_env.json
      in terminal 2: ./build_ci.sh --qemu --config build_amd_env.json
      in terminal 3: ./build_ci.sh --vf --config build_amd_env.json

    - If you are in Xilinx netowrk
      in terminal 1: ./build_ci.sh --simnow --config build_xlnx_env.json
      in terminal 2: ./build_ci.sh --qemu --config build_xlnx_env.json
      in terminal 3: ./build_ci.sh --vf --config build_xlnx_env.json

Warn:
  The build_ci.json is for pipeline test only.

```

## How to start simnow endpoint mode manually
  see README in sub directory simnow-0515+

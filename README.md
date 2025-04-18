This repository is a fork of the OpenAirInterface (OAI) project and includes the following modifications:

Enabled the SMF to subscribe to the NWDAF and receive periodic notifications.

Enabled the SMF to release the PDU session of abnormal UEs based on NWDAF notifications.

Additionally, introduced experimental modifications to PFCP messages as part of our own research.


------------------------------------------------------------------------------

                             OPENAIR-CN-5G
 An implementation of the 5G Core network by the OpenAirInterface community.

------------------------------------------------------------------------------

OPENAIR-CN-5G is an implementation of the 3GPP specifications for the 5G Core Network.
At the moment, it contains the following network elements:

* Access and Mobility Management Function (**AMF**)
* Authentication Server Management Function (**AUSF**)
* Location Management Function (**LMF**)
* Network Exposure Function (**NEF**)
* Network Slicing Selection Function (**NSSF**)
* Network Repository Function (**NRF**)
* Network Data Analytics Function (**NWDAF**)
* Policy Control Function (**PCF**)
* Session Management Function (**SMF**)
* Unified Data Management (**UDM**)
* Unified Data Repository (**UDR**)
* Unstructured Data Storage Function (**UDSF**)
* User Plane Function (**UPF**)

Each has its own repository: this repository (`oai-cn5g-smf`) is meant for SMF.

# Licence info

It is distributed under `OAI Public License V1.1`.
See [OAI Website for more details](https://www.openairinterface.org/?page_id=698).

The text for `OAI Public License V1.1` is also available under [LICENSE](LICENSE)
file at the root of this repository.

# Where to start

The Openair-CN-5G SMF code is written, executed, and tested on UBUNTU server bionic version.
Other Linux distributions support will be added later on.

More details on the supported feature set is available on this [page](docs/FEATURE_SET.md).

# Collaborative work

This source code is managed through a GITLAB server, a collaborative development platform:

*  URL: [https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-smf](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-smf).

Process is explained in [CONTRIBUTING](CONTRIBUTING.md) file.

# Contribution requests

In a general way, anybody who is willing can contribute on any part of the
code in any network component.

Contributions can be simple bugfixes, advices and remarks on the design,
architecture, coding/implementation.

# Release Notes

They are available on the [CHANGELOG](CHANGELOG.md) file.

# Repository Structure:

The OpenAirInterface CN SMF software is composed of the following parts: 

<pre>
openair-cn5g-smf
├── 3gpp-specs:    Directory containing 3GPP specification files (YAML) used to implement SMF network function. 
├── build:         Build directory, contains targets and object files generated by compilation of network functions. 
    ├── log:       Directory containing build log files.
    ├── scripts:   Directory containing scripts for building network functions.
    └── smf:       Directory containing CMakefile.txt and object files generated by compilation of SMF network function. 
├── ci-scripts:    Directory containing the script files for CI framework.
├── docs:          Directory containing the documentation files.
├── etc:           Directory containing the configuration file to be deployed for SMF.
└── src:           Source files of SMF.
    ├── api-server: SMF services APIs. 
    ├── common:    Common header files
    │   ├── msg:   ITTI messages definitions.
    │   └── utils: Common utilities.
    ├── itti:      Inter task interface.
    ├── nas:       NAS protocol implememtation.
    ├── ngap:      NGAP protocol implememtation.
    ├── oai_smf:   SMF main directory, contains the "main" CMakeLists.txt file.
    ├── pfcp:      Generic PFCP stack implementation.
    ├── smf_app:   SMF network functions procedures and contexts.
    └── udp :      UDP server implementation.
</pre>

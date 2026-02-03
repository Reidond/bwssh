"""SSH agent protocol constants.

Per IETF draft-miller-ssh-agent-17 and OpenSSH PROTOCOL.agent.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

SSH_AGENT_FAILURE: int = 5
SSH_AGENT_SUCCESS: int = 6

SSH_AGENTC_REQUEST_IDENTITIES: int = 11
SSH_AGENT_IDENTITIES_ANSWER: int = 12

SSH_AGENTC_SIGN_REQUEST: int = 13
SSH_AGENT_SIGN_RESPONSE: int = 14

SSH_AGENTC_ADD_IDENTITY: int = 17
SSH_AGENTC_REMOVE_IDENTITY: int = 18
SSH_AGENTC_REMOVE_ALL_IDENTITIES: int = 19

SSH_AGENTC_LOCK: int = 22
SSH_AGENTC_UNLOCK: int = 23

SSH_AGENTC_ADD_ID_CONSTRAINED: int = 25

SSH_AGENTC_EXTENSION: int = 27

SSH_AGENT_RSA_SHA2_256: int = 0x02
SSH_AGENT_RSA_SHA2_512: int = 0x04

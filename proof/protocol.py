# The MIT License (MIT)
# Copyright © 2023 Yuma Rao
# TODO(developer): Set your name
# Copyright © 2023 <your name>

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import typing
import bittensor as bt


class Store(bt.Synapse):
    class Config:
        validate_assignment = True

    def deserialize(self) -> str:
        return self.zk_proof

    # Query values
    content: typing.Optional[object] = pydantic.Field(..., allow_mutation=False)
    content_hash: str = pydantic.Field(..., allow_mutation=False)
    pubkey: str = pydantic.Field(..., allow_mutation=False)
    signature: str = pydantic.Field(..., allow_mutation=False)

    # Return values
    verified: typing.Optional[str] = ''

class Retrieve(bt.Synapse):
    class Config:
        validate_assignment = True

    def deserialize(self) -> str:
        return self.verified

    # Query values
    content_hash: str = pydantic.Field(..., allow_mutation=False)

    # Return values
    in_registry: typing.Optional[bool] = False
    miner_signature: typing.Optional[str] = ''
    miner_pubkey: typing.Optional[str] = ''
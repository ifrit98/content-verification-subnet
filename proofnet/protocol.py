# The MIT License (MIT)
# Copyright © 2023 Yuma Rao
# Copyright © 2023 philanthrope

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

import pydantic
import bittensor as bt
from typing import List, Dict, Tuple, Optional

class Store(bt.Synapse):
    class Config:
        validate_assignment = True

    def deserialize(self) -> bool:
        return self

    # Query values
    content: Optional[object] = pydantic.Field(..., allow_mutation=False)
    content_hash: str = pydantic.Field(..., allow_mutation=False)
    pubkey: str = pydantic.Field(..., allow_mutation=False)
    signature: str = pydantic.Field(..., allow_mutation=False)

    # Return values
    stored: Optional[bool] = False

class Retrieve(bt.Synapse):
    class Config:
        validate_assignment = True

    def deserialize(self) -> List[Dict[str, Tuple[str, str]]]:
        return self.miner_data

    # Query values
    registry_indices: List[int] = pydantic.Field(..., allow_mutation=False)

    # Return values
    miner_data: Optional[List[Dict[str, Tuple[str, str]]]] = {}


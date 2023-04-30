# Copyright 2022 Cartesi Pte. Ltd.
#
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License. You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.


class Balance():
    """
    Holds and manipulates an account's balance for ERC-20 and ERC-721 tokens
    """

    def __init__(self, account: str,
                 erc20: dict[str: int] = None):
        self._account = account
        self._erc20 = erc20 if erc20 else {}

    def erc20_get(self, erc20: str) -> int:
        return self._erc20.get(erc20, 0)

    def _erc20_increase(self, erc20: str, amount: int):
        if amount < 0:
            raise ValueError(
                f"Failed to increase {erc20} balance for {self._account}. "
                f"{amount} should be a positive number")

        self._erc20[erc20] = self._erc20.get(erc20, 0) + amount

    def _erc20_decrease(self, erc20: str, amount: int):
        if amount < 0:
            raise ValueError(
                f"Failed to decrease {erc20} balance for {self._account}. "
                f"{amount} should be a positive number")

        erc20_balance = self._erc20.get(erc20, 0)
        if erc20_balance < amount:
            raise ValueError(
                f"Failed to decrease {erc20} balance for {self._account}. "
                f"Not enough funds to decrease {amount}")

        self._erc20[erc20] = erc20_balance - amount

    
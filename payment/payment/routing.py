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

import json
from datetime import datetime
from urllib.parse import parse_qs, urlparse

import payment.wallet as Wallet
from payment.encoders import BalanceEncoder
from payment.log import logger
from payment.outputs import Error, Log
from payment.util import hex_to_str
from routes import Mapper


class DefaultRoute():

    def execute(self, match_result, request=None):
        return Error("Operation not implemented")


class AdvanceRoute(DefaultRoute):

    def _parse_request(self, request):
        self._msg_sender = request["metadata"]["msg_sender"]
        self._msg_timestamp = datetime.fromtimestamp(
            request["metadata"]["timestamp"])
        request_payload = json.loads(
            hex_to_str(request["payload"]))
        self._request_args = request_payload["args"]

    def execute(self, match_result, request=None):
        if request:
            self._parse_request(request)


class WalletRoute(AdvanceRoute):

    def __init__(self, wallet: Wallet):
        self._wallet = wallet


class DepositRoute(WalletRoute):

    def execute(self, match_result, request=None):
        return self._wallet.deposit_process(request)


class BalanceRoute(WalletRoute):

    def execute(self, match_result, request=None):
        account = match_result["account"]
        balance = self._wallet.balance_get(account)
        return Log(json.dumps(balance, cls=BalanceEncoder))


class WithdrawErc20Route(WalletRoute):

    def execute(self, match_result, request=None):
        super().execute(match_result, request)
        return self._wallet.erc20_withdraw(self._msg_sender,
                                           self._request_args.get(
                                               "erc20").lower(),
                                           self._request_args.get("amount"))


class TransferErc20Route(WalletRoute):

    def execute(self, match_result, request=None):
        super().execute(match_result, request)
        return self._wallet.erc20_transfer(self._msg_sender,
                                           self._request_args.get(
                                               "to").lower(),
                                           self._request_args.get(
                                               "erc20").lower(),
                                           self._request_args.get("amount"))



class Router():

    def __init__(self, rollup_address, wallet):
        self._controllers = {
            "deposit": DepositRoute(wallet),
            "balance": BalanceRoute(wallet),
            "erc20_withdraw": WithdrawErc20Route(wallet),
            "erc20_transfer": TransferErc20Route(wallet),
        }

        self._route_map = Mapper()


        self._route_map.connect(None,
                                "deposit",
                                controller="deposit",
                                action="execute")
        self._route_map.connect(None,
                                "balance/{account}",
                                controller="balance",
                                action="execute")

        self._route_map.connect(None,
                                "erc20withdrawal",
                                controller="erc20_withdraw",
                                action="execute")

        self._route_map.connect(None,
                                "erc20transfer",
                                controller="erc20_transfer",
                                action="execute")

    def process(self, route, request=None):
        route = route.lower()
        match_result = self._route_map.match(route)
        if match_result is None:
            return Error(f"Operation '{route}' is not supported")
        else:
            controller = self._controllers.get(match_result["controller"])
            logger.info(f"Executing operation '{route}'")
            return controller.execute(match_result, request)

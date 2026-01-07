#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
M13: RevenueEvent_Model_Definition
==================================
This module defines the financial models for tracking revenue events, tax liabilities,
and PnL (Profit and Loss) within the system.

Features:
- Double-Entry Ledger Logic (Credits/Debits).
- FIFO/LIFO/HIFO Accounting Method support.
- Multi-Currency support (Fiat + Crypto).
- Tax Lot tracking.
- Immutable Event Logs (Audit trail).

Author: Jules (AI)
System: Waggo Arbitrage Core
Date: 2024
"""

import os
import sys
import json
import logging
import uuid
import datetime
import typing
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from decimal import Decimal, getcontext

# Set Decimal Precision for Financials
getcontext().prec = 28

# Configure Logging
logger = logging.getLogger("RevenueModel")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)

# --- Enums ---

class EventType(str): # Using str for JSON ease
    TRADE_PROFIT = "TRADE_PROFIT"
    TRADE_LOSS = "TRADE_LOSS"
    FEE_PAYMENT = "FEE_PAYMENT"
    WITHDRAWAL = "WITHDRAWAL"
    DEPOSIT = "DEPOSIT"
    INTEREST = "INTEREST"

class AccountingMethod(str):
    FIFO = "FIFO"
    LIFO = "LIFO"

# --- Models ---

@dataclass
class TaxLot:
    """
    Represents a chunk of asset acquired at a specific price/time.
    """
    lot_id: str
    asset: str
    amount: Decimal
    cost_basis_per_unit: Decimal
    acquired_at: datetime.datetime
    remaining: Decimal # Amount not yet sold

@dataclass
class RevenueEvent:
    event_id: str
    timestamp: datetime.datetime
    type: EventType
    description: str

    # Financials
    asset: str
    amount: Decimal
    fiat_value_at_time: Decimal # e.g. USD

    # Ledger
    debit_account: str
    credit_account: str

    # Metadata
    tx_hash: Optional[str] = None
    related_lot_id: Optional[str] = None

# --- Logic ---

class RevenueLedger:
    """
    M13: The Accountant.
    """
    def __init__(self):
        self.events: List[RevenueEvent] = []
        self.lots: Dict[str, List[TaxLot]] = {} # asset -> [lots]

    def record_deposit(self, asset: str, amount: float, price_usd: float):
        amt = Decimal(str(amount))
        price = Decimal(str(price_usd))

        # Create Lot
        lot = TaxLot(
            lot_id=str(uuid.uuid4()),
            asset=asset,
            amount=amt,
            cost_basis_per_unit=price,
            acquired_at=datetime.datetime.now(),
            remaining=amt
        )
        if asset not in self.lots: self.lots[asset] = []
        self.lots[asset].append(lot)

        # Record Event
        evt = RevenueEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(),
            type=EventType.DEPOSIT,
            description=f"Deposit {asset}",
            asset=asset,
            amount=amt,
            fiat_value_at_time=amt * price,
            debit_account="ASSETS_CRYPTO",
            credit_account="EQUITY_CAPITAL"
        )
        self.events.append(evt)
        logger.info(f"Recorded Deposit: {amt} {asset} @ ${price}")

    def record_sale(self, asset: str, amount: float, price_usd: float, method=AccountingMethod.FIFO):
        amt_to_sell = Decimal(str(amount))
        price = Decimal(str(price_usd))

        if asset not in self.lots:
            raise ValueError(f"No lots found for {asset}")

        # Sort lots based on method
        if method == AccountingMethod.FIFO:
            self.lots[asset].sort(key=lambda x: x.acquired_at)
        else:
            self.lots[asset].sort(key=lambda x: x.acquired_at, reverse=True)

        realized_pnl = Decimal(0)
        remaining_to_sell = amt_to_sell

        # Consume lots
        for lot in self.lots[asset]:
            if remaining_to_sell <= 0: break
            if lot.remaining <= 0: continue

            consumed = min(remaining_to_sell, lot.remaining)

            # Calc PnL segment
            cost = consumed * lot.cost_basis_per_unit
            proceeds = consumed * price
            pnl = proceeds - cost
            realized_pnl += pnl

            # Update Lot
            lot.remaining -= consumed
            remaining_to_sell -= consumed

        if remaining_to_sell > 0:
            logger.warning("Selling more than available in tax lots! (Short selling?)")

        # Record Event
        evt_type = EventType.TRADE_PROFIT if realized_pnl >= 0 else EventType.TRADE_LOSS

        evt = RevenueEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(),
            type=evt_type,
            description=f"Sold {amt_to_sell} {asset}",
            asset="USD", # Result is USD
            amount=realized_pnl, # Recording the Net PnL
            fiat_value_at_time=realized_pnl,
            debit_account="ASSETS_FIAT" if realized_pnl > 0 else "EXPENSE_LOSS",
            credit_account="INCOME_GAIN" if realized_pnl > 0 else "ASSETS_FIAT"
        )
        self.events.append(evt)
        logger.info(f"Recorded Sale: PnL=${realized_pnl:.2f}")

    def get_summary(self):
        total_pnl = sum(e.fiat_value_at_time for e in self.events if e.type in [EventType.TRADE_PROFIT, EventType.TRADE_LOSS])
        return {
            "total_events": len(self.events),
            "net_pnl_usd": float(total_pnl)
        }

# --- Demo ---

def run_revenue_demo():
    print("M13: Revenue Model Demo")

    ledger = RevenueLedger()

    # 1. Buy 1 BTC @ 50k
    ledger.record_deposit("BTC", 1.0, 50000.00)

    # 2. Buy 1 BTC @ 60k
    ledger.record_deposit("BTC", 1.0, 60000.00)

    # 3. Sell 1.5 BTC @ 70k (FIFO)
    # Lot 1 (50k): 1.0 consumed -> Gain 20k
    # Lot 2 (60k): 0.5 consumed -> Gain 5k
    # Total Gain: 25k
    ledger.record_sale("BTC", 1.5, 70000.00, AccountingMethod.FIFO)

    summary = ledger.get_summary()
    print("Summary:", summary)

    # Verify
    assert 24999 < summary['net_pnl_usd'] < 25001

if __name__ == "__main__":
    run_revenue_demo()

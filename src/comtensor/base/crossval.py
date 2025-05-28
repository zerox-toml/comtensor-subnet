from abc import ABC, abstractmethod
import bittensor as bt
import threading
import time
from typing import Dict, List, Optional
from .security import SecurityManager
from .rate_limiter import RateLimiter

class BaseCrossval(ABC):
    def __init__(self, netuid = 1, wallet_name = None, wallet_hotkey = None, network = "finney", topk = 1, subtensor = None):
        self.netuid = netuid
        if wallet_name is not None and wallet_hotkey is not None:
            try:
                self.wallet = bt.wallet(name=wallet_name, hotkey=wallet_hotkey)
            except Exception as e:
                bt.logging.error(f"Error occurred while importing wallet: {e}")
                self.wallet = None
        if subtensor is not None:
            self.subtensor = subtensor
        else:
            self.subtensor = bt.subtensor(network = network)
        bt.logging.info(f"Syncing metagraph on netuid: {self.netuid}")
        self.metagraph = self.subtensor.metagraph(netuid = self.netuid)
        self.topk = topk
        self.top_miners = self.get_top_miners()
        self.block = self.subtensor.block
        self.is_thread_running = False
        
        # Initialize security and rate limiting
        self.security_manager = SecurityManager()
        self.rate_limiter = RateLimiter()
        
        # Start cleanup thread for rate limiter
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

    def _cleanup_loop(self):
        """Background thread to clean up rate limiter and security manager."""
        while True:
            try:
                self.rate_limiter.cleanup()
                self.security_manager.cleanup_expired_nonces()
                time.sleep(60)  # Clean up every minute
            except Exception as e:
                bt.logging.error(f"Error in cleanup loop: {e}")

    def check_wallet(self):
        """Check if wallet is properly initialized and registered."""
        if self.wallet is None:
            raise Exception("Wallet not initialized.")
        if self.wallet.hotkey.ss58_address not in self.metagraph.hotkeys:
            raise Exception("Wallet not registered to subnet.")
        if self.metagraph.hotkeys[self.wallet.hotkey.ss58_address].stake < 1:
            raise Exception("Wallet not staked with enough stake.")

    def verify_miner(self, miner_uid: int, signature: str, nonce: str) -> bool:
        """Verify miner's signature and nonce."""
        try:
            miner_hotkey = self.metagraph.hotkeys[miner_uid]
            message = f"{miner_uid}{nonce}"
            return (
                self.security_manager.verify_signature(message, signature, miner_hotkey) and
                self.security_manager.verify_nonce(nonce)
            )
        except Exception as e:
            bt.logging.error(f"Error verifying miner {miner_uid}: {e}")
            return False

    def get_top_miners(self) -> List[Dict]:
        """Get top K miners from metagraph with security checks."""
        metagraph_json = [{
            "netuid": self.netuid,
            "uid": i,
            "ip": axon.ip,
            "port": axon.port,
            "coldkey": axon.coldkey,
            "hotkey": axon.hotkey,
            "active": axon.is_serving,
            "rank": self.metagraph.ranks[i].item(),
            "v_trust": self.metagraph.validator_trust[i].item(),
            "v_permit": self.metagraph.validator_permit[i].item(),
            "trust": self.metagraph.trust[i].item(),
            "consensus": self.metagraph.consensus[i].item(),
            "incentive": self.metagraph.incentive[i].item(),
            "dividends": self.metagraph.dividends[i].item(),
            "emission": self.metagraph.emission[i].item(),
            "stake": self.metagraph.stake[i].item(),
            "last_update": self.metagraph.last_update[i].item(),
        } for i, axon in enumerate(self.metagraph.axons)]

        # Sort by emission and filter out validators
        metagraph_json.sort(key=lambda x: x['emission'], reverse=True)
        top_miners = []
        for item in metagraph_json:
            if item['v_trust'] > 0:
                continue
            if len(top_miners) >= self.topk:
                break
            top_miners.append(item)
        
        return top_miners

    def run_thread(self):
        """Main thread for running validation."""
        while True:
            try:
                self.resync_metagraph()
                self.top_miners = self.get_top_miners()
                self.run_custom_thread()
                self.block = self.subtensor.block
                time.sleep(120)
            except Exception as e:
                bt.logging.error(f"Error in run thread: {e}")
                time.sleep(60)  # Wait before retrying

    @abstractmethod
    def run_custom_thread(self):
        """Custom thread implementation to be defined by subclasses."""
        pass

    def run_background_thread(self):
        """Start the background thread if not already running."""
        if not self.is_thread_running:
            self.thread = threading.Thread(target=self.run_thread)
            self.thread.start()
            self.is_thread_running = True
            bt.logging.info("Thread started")

    def stop_background_thread(self):
        if self.is_thread_running:
            self.is_thread_running = False
            self.thread.join(5)
            bt.logging.info("Thread stopped")

    def __enter__(self):
        self.run_background_thread()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop_background_thread()

    def resync_metagraph(self):
        bt.logging.info("resync_metagraph")
        self.metagraph.sync(subtensor = self.subtensor)
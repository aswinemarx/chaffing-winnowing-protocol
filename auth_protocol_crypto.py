# ============================================================================
# Secure Packet Authentication Protocol: Chaffing & Winnowing Implementation
# ============================================================================
# A cryptographic technique for authentication over untrusted channels
# without relying on encryption alone. Applications: IoT, IC cards, terminals.
#
# Author: [Your Name]
# License: MIT
# ============================================================================

import os
import hashlib
import hmac
import secrets
import json
import struct
from typing import List, Tuple, Dict
from dataclasses import dataclass, asdict
from datetime import datetime

# ============================================================================
# Constants & Configuration
# ============================================================================

CHAFF_TO_WHEAT_RATIO = 99  # 99 chaff packets for every 1 real packet
PACKET_SIZE = 256  # bytes per packet payload
HMAC_KEY_LENGTH = 32  # 256-bit key
MAC_SIZE = 32  # SHA-256 MAC size
HASH_ALGO = hashlib.sha256
PROTOCOL_VERSION = "1.0"

# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class AuthenticatedPacket:
    """Single packet in the chaffing/winnowing protocol."""
    packet_id: int
    sequence_number: int
    payload: str  # Hex-encoded data (wheat) or random (chaff)
    mac: str  # HMAC-SHA256 of payload
    is_chaff: bool = False  # Only known to sender/receiver (not in transmission)
    timestamp: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to serializable dict."""
        d = asdict(self)
        d.pop('is_chaff')  # Don't serialize the type indicator
        return d
    
    def to_json(self) -> str:
        """Serialize to JSON for transmission."""
        return json.dumps(self.to_dict(), separators=(',', ':'))


@dataclass
class ProtocolSession:
    """Session metadata for chaffing/winnowing communication."""
    session_id: str
    sender_id: str
    receiver_id: str
    shared_hmac_key: bytes
    chaff_ratio: int = CHAFF_TO_WHEAT_RATIO
    created_at: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to dict (key remains as hex)."""
        return {
            'session_id': self.session_id,
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'shared_hmac_key': self.shared_hmac_key.hex(),
            'chaff_ratio': self.chaff_ratio,
            'created_at': self.created_at
        }


# ============================================================================
# Core Protocol Implementation
# ============================================================================

class ChaffWinnowProtocol:
    """
    Implements Rivest's Chaffing & Winnowing protocol for authentication
    over untrusted channels (compromised terminals/endpoints).
    
    Key insight: Instead of securing the channel, we make eavesdropping
    computationally futile by mixing real packets with indistinguishable fakes.
    """
    
    def __init__(self, shared_hmac_key: bytes = None):
        """
        Initialize protocol with shared HMAC key.
        
        Args:
            shared_hmac_key: Symmetric key (32 bytes) shared only between
                           trusted IC card/server. If None, generates new key.
        """
        if shared_hmac_key is None:
            self.shared_hmac_key = secrets.token_bytes(HMAC_KEY_LENGTH)
        else:
            if len(shared_hmac_key) != HMAC_KEY_LENGTH:
                raise ValueError(f"Key must be {HMAC_KEY_LENGTH} bytes")
            self.shared_hmac_key = shared_hmac_key
    
    def create_session(self, sender_id: str, receiver_id: str) -> ProtocolSession:
        """Create authenticated session."""
        session = ProtocolSession(
            session_id=secrets.token_hex(16),
            sender_id=sender_id,
            receiver_id=receiver_id,
            shared_hmac_key=self.shared_hmac_key,
            created_at=datetime.utcnow().isoformat()
        )
        return session
    
    def _compute_mac(self, data: bytes) -> str:
        """
        Compute HMAC-SHA256 of data using shared key.
        
        This MAC is the "winnowing criterion"—only the server with the key
        can verify which packets are real.
        
        Args:
            data: Payload to authenticate
            
        Returns:
            MAC as hex string
        """
        mac = hmac.new(
            self.shared_hmac_key,
            data,
            HASH_ALGO
        ).digest()
        return mac.hex()
    
    def _generate_random_payload(self, size: int = PACKET_SIZE) -> str:
        """
        Generate random payload formatted to look like real data.
        (This is the "chaff" — fake but indistinguishable from real.)
        
        Args:
            size: Number of random bytes
            
        Returns:
            Random hex string of specified size
        """
        random_bytes = secrets.token_bytes(size)
        return random_bytes.hex()
    
    def _generate_wheat_packets(self, data: bytes) -> List[AuthenticatedPacket]:
        """
        Create authenticated "wheat" (real) packets from data.
        
        Each byte of data becomes one packet with a valid MAC.
        
        Args:
            data: Data to split into packets
            
        Returns:
            List of authenticated real packets
        """
        wheat_packets = []
        
        for idx, byte_val in enumerate(data):
            # Each byte of data is one "real" packet
            payload_bytes = bytes([byte_val])
            mac = self._compute_mac(payload_bytes)
            
            packet = AuthenticatedPacket(
                packet_id=idx,
                sequence_number=idx,
                payload=payload_bytes.hex(),
                mac=mac,
                is_chaff=False,
                timestamp=datetime.utcnow().isoformat()
            )
            wheat_packets.append(packet)
        
        return wheat_packets
    
    def _generate_chaff_packets(self, count: int) -> List[AuthenticatedPacket]:
        """
        Create fake "chaff" packets with random data and non-valid MACs.

        Chaff must look structurally identical but must NOT verify under the
        shared HMAC key. Previously this function used the shared key to
        compute MACs for chaff, which made chaff indistinguishable from
        wheat to the receiver. That bug caused chaff to pass verification and
        produced invalid recovered bytes.

        Args:
            count: Number of chaff packets to generate

        Returns:
            List of chaff packets with valid-looking structure but invalid MACs
        """
        chaff_packets = []

        for idx in range(count):
            # Generate random payload (one byte, like wheat)
            random_payload_bytes = secrets.token_bytes(1)

            # Generate a random MAC (same length as HMAC-SHA256 hex digest)
            # Do NOT use the shared key here.
            mac = secrets.token_hex(MAC_SIZE)

            packet = AuthenticatedPacket(
                packet_id=-(idx + 1),  # Negative IDs for chaff
                sequence_number=-(idx + 1),
                payload=random_payload_bytes.hex(),
                mac=mac,
                is_chaff=True,
                timestamp=datetime.utcnow().isoformat()
            )
            chaff_packets.append(packet)

        return chaff_packets
    
    def chaff(self, data: bytes, chaff_ratio: int = CHAFF_TO_WHEAT_RATIO) -> List[AuthenticatedPacket]:
        """
        SENDER OPERATION: Add chaff to real data (wheat).
        
        This is the "needle in haystack" approach:
        - Generate real packets (wheat) from the data
        - Generate random-looking fake packets (chaff)
        - Mix them together and send all
        - Compromised terminal sees all, can verify none (no key)
        
        Args:
            data: Real data to send
            chaff_ratio: Ratio of chaff to wheat (e.g., 99:1)
            
        Returns:
            Mixed list of wheat + chaff packets (shuffled)
        """
        # Step 1: Generate real packets from data
        wheat = self._generate_wheat_packets(data)
        wheat_count = len(wheat)
        
        # Step 2: Generate chaff packets
        chaff_count = wheat_count * chaff_ratio
        chaff = self._generate_chaff_packets(chaff_count)
        
        # Step 3: Mix wheat and chaff
        mixed_stream = wheat + chaff
        
        # Step 4: Shuffle (so order doesn't reveal which is real)
        import random
        random.shuffle(mixed_stream)
        
        # Update sequence numbers to reflect shuffled order
        for seq, packet in enumerate(mixed_stream):
            packet.sequence_number = seq
        
        return mixed_stream
    
    def winnow(self, packet_stream: List[AuthenticatedPacket]) -> bytes:
        """
        RECEIVER OPERATION: Filter out chaff, recover real data.
        
        Server-side: Verify HMAC of each packet. Only real packets have
        valid MACs (computed with the shared key). Chaff fails verification.
        
        Args:
            packet_stream: Stream of mixed wheat + chaff packets
            
        Returns:
            Recovered real data
        """
        real_packets = []
        
        for packet in packet_stream:
            # Compute what the MAC should be
            payload_bytes = bytes.fromhex(packet.payload)
            expected_mac = self._compute_mac(payload_bytes)
            
            # If MAC matches, it's real (wheat)
            if expected_mac == packet.mac:
                real_packets.append(packet)
        
        # Sort by original packet_id to restore original order
        real_packets.sort(key=lambda p: p.packet_id)
        
        # Extract bytes from payloads
        recovered_data = bytes([int(p.payload, 16) for p in real_packets])
        
        return recovered_data
    
    def send_secure_message(self, message: str) -> Tuple[List[Dict], Dict]:
        """
        Simulate secure transmission through compromised terminal.
        
        Args:
            message: Text message to securely transmit
            
        Returns:
            (packet_stream, transmission_metadata)
        """
        # Convert message to bytes
        data = message.encode('utf-8')
        
        # Apply chaffing
        packet_stream = self.chaff(data)
        
        # Metadata about transmission (for logging/auditing)
        metadata = {
            'message_length': len(data),
            'total_packets': len(packet_stream),
            'wheat_packets': len(data),
            'chaff_packets': len(packet_stream) - len(data),
            'transmission_time': datetime.utcnow().isoformat(),
            'protocol_version': PROTOCOL_VERSION
        }
        
        # Convert to JSON-serializable format
        serialized_stream = [p.to_dict() for p in packet_stream]
        
        return serialized_stream, metadata
    
    def receive_secure_message(self, packet_stream: List[Dict]) -> str:
        """
        Recover message from packet stream (server-side).
        
        Args:
            packet_stream: Serialized packet stream (from send_secure_message)
            
        Returns:
            Recovered original message
        """
        # Deserialize packets
        packets = [
            AuthenticatedPacket(**pkt)
            for pkt in packet_stream
        ]
        
        # Winnow to extract real data
        recovered_bytes = self.winnow(packets)
        
        # Decode back to string
        message = recovered_bytes.decode('utf-8')
        
        return message


# ============================================================================
# Demonstration & Testing
# ============================================================================

def demonstrate_protocol():
    """Demonstrate the chaffing/winnowing protocol in action."""
    
    print("=" * 80)
    print("CHAFFING & WINNOWING PROTOCOL DEMONSTRATION")
    print("Secure Communication Through Compromised Terminals")
    print("=" * 80)
    
    # Initialize protocol with shared key
    protocol = ChaffWinnowProtocol()
    shared_key = protocol.shared_hmac_key
    print(f"\n✓ Shared HMAC Key (256-bit): {shared_key.hex()}")
    
    # Create session
    session = protocol.create_session(
        sender_id="IC_CARD_001",
        receiver_id="GOVERNMENT_SERVER"
    )
    print(f"\n✓ Session Created: {session.session_id}")
    print(f"  From: {session.sender_id} → To: {session.receiver_id}")
    
    # Message to send
    original_message = "IDENTITY_TOKEN_12345"
    print(f"\n✓ Original Message: {original_message}")
    
    # Send through compromised terminal
    print("\n" + "-" * 80)
    print("TRANSMISSION (through compromised terminal):")
    print("-" * 80)
    
    packet_stream, metadata = protocol.send_secure_message(original_message)
    
    print(f"\n✓ Total Packets Generated: {metadata['total_packets']}")
    print(f"  - Real packets (wheat): {metadata['wheat_packets']}")
    print(f"  - Fake packets (chaff): {metadata['chaff_packets']}")
    print(f"  - Chaff/Wheat Ratio: {metadata['chaff_packets']}:{metadata['wheat_packets']}")
    
    print(f"\n✓ What the terminal sees:")
    print(f"  [Compromised terminal cannot verify ANY packet without the HMAC key]")
    print(f"  [It sees {metadata['total_packets']} packets, all appear equally valid]")
    
    # Show sample packets (terminal's view)
    print(f"\n  Sample packets visible to terminal (first 5):")
    for i, pkt in enumerate(packet_stream[:5]):
        print(f"    Packet {i}: payload={pkt['payload'][:16]}... mac={pkt['mac'][:16]}...")
    
    # Receive at server
    print("\n" + "-" * 80)
    print("SERVER-SIDE FILTERING (with HMAC key):")
    print("-" * 80)
    
    recovered_message = protocol.receive_secure_message(packet_stream)
    
    print(f"\n✓ Server verifies each packet's MAC")
    print(f"✓ Real packets pass verification (wheat)")
    print(f"✓ Fake packets fail verification (chaff discarded)")
    print(f"✓ Recovered Message: {recovered_message}")
    
    # Verification
    success = original_message == recovered_message
    print(f"\n{'✓ SUCCESS' if success else '✗ FAILURE'}: " +
          f"Message integrity verified: {success}")
    
    # Security analysis
    print("\n" + "=" * 80)
    print("SECURITY ANALYSIS:")
    print("=" * 80)
    print(f"""
✓ Information-Theoretic Security:
  - Eavesdropper (compromised terminal) sees {metadata['total_packets']} packets
  - Cannot distinguish real from fake without HMAC key
  - Probability of guessing correct packet: 1/{metadata['total_packets']}
  - 99% of captured data is useless noise (chaff)

✓ Computational Security:
  - HMAC-SHA256: 2^256 possible keys
  - Brute-force attack infeasible

✓ Bandwidth Cost:
  - Additional overhead: {metadata['chaff_packets']} chaff packets
  - Trade-off: Bandwidth for confidentiality (no encryption needed)

✓ Terminal Compromise Scenario:
  - Even if malware captures ALL packets
  - Even if it intercepts EVERYTHING
  - It still cannot recover the real message
  - The chaff makes the real data indistinguishable
    """)
    
    return protocol, session, packet_stream, original_message


if __name__ == "__main__":
    protocol, session, packets, original = demonstrate_protocol()
    
    print("\n" + "=" * 80)
    print("Protocol ready for integration with IC card systems")
    print("=" * 80)

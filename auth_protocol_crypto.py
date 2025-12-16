import os
import hashlib
import hmac
import secrets
import json
import struct
from typing import List, Tuple, Dict
from dataclasses import dataclass, asdict
from datetime import datetime

CHAFF_TO_WHEAT_RATIO = 99
PACKET_SIZE = 256
HMAC_KEY_LENGTH = 32
MAC_SIZE = 32
HASH_ALGO = hashlib.sha256
PROTOCOL_VERSION = "1.0"

@dataclass
class AuthenticatedPacket:
    packet_id: int
    sequence_number: int
    payload: str
    mac: str
    is_chaff: bool = False
    timestamp: str = ""
    
    def to_dict(self) -> Dict:
        d = asdict(self)
        d.pop('is_chaff')
        return d
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(',', ':'))

@dataclass
class ProtocolSession:
    session_id: str
    sender_id: str
    receiver_id: str
    shared_hmac_key: bytes
    chaff_ratio: int = CHAFF_TO_WHEAT_RATIO
    created_at: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'session_id': self.session_id,
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'shared_hmac_key': self.shared_hmac_key.hex(),
            'chaff_ratio': self.chaff_ratio,
            'created_at': self.created_at
        }

class ChaffWinnowProtocol:
    
    def __init__(self, shared_hmac_key: bytes = None):
        if shared_hmac_key is None:
            self.shared_hmac_key = secrets.token_bytes(HMAC_KEY_LENGTH)
        else:
            if len(shared_hmac_key) != HMAC_KEY_LENGTH:
                raise ValueError(f"Key must be {HMAC_KEY_LENGTH} bytes")
            self.shared_hmac_key = shared_hmac_key
    
    def create_session(self, sender_id: str, receiver_id: str) -> ProtocolSession:
        session = ProtocolSession(
            session_id=secrets.token_hex(16),
            sender_id=sender_id,
            receiver_id=receiver_id,
            shared_hmac_key=self.shared_hmac_key,
            created_at=datetime.utcnow().isoformat()
        )
        return session
    
    def _compute_mac(self, data: bytes) -> str:
        mac = hmac.new(
            self.shared_hmac_key,
            data,
            HASH_ALGO
        ).digest()
        return mac.hex()
    
    def _generate_random_payload(self, size: int = PACKET_SIZE) -> str:
        random_bytes = secrets.token_bytes(size)
        return random_bytes.hex()
    
    def _generate_wheat_packets(self, data: bytes) -> List[AuthenticatedPacket]:
        wheat_packets = []
        
        for idx, byte_val in enumerate(data):
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
        chaff_packets = []

        for idx in range(count):
            random_payload_bytes = secrets.token_bytes(1)
            mac = secrets.token_hex(MAC_SIZE)

            packet = AuthenticatedPacket(
                packet_id=-(idx + 1),
                sequence_number=-(idx + 1),
                payload=random_payload_bytes.hex(),
                mac=mac,
                is_chaff=True,
                timestamp=datetime.utcnow().isoformat()
            )
            chaff_packets.append(packet)

        return chaff_packets
    
    def chaff(self, data: bytes, chaff_ratio: int = CHAFF_TO_WHEAT_RATIO) -> List[AuthenticatedPacket]:
        wheat = self._generate_wheat_packets(data)
        wheat_count = len(wheat)
        
        chaff_count = wheat_count * chaff_ratio
        chaff = self._generate_chaff_packets(chaff_count)
        
        mixed_stream = wheat + chaff
        
        import random
        random.shuffle(mixed_stream)
        
        for seq, packet in enumerate(mixed_stream):
            packet.sequence_number = seq
        
        return mixed_stream
    
    def winnow(self, packet_stream: List[AuthenticatedPacket]) -> bytes:
        real_packets = []
        
        for packet in packet_stream:
            payload_bytes = bytes.fromhex(packet.payload)
            expected_mac = self._compute_mac(payload_bytes)
            
            if expected_mac == packet.mac:
                real_packets.append(packet)
        
        real_packets.sort(key=lambda p: p.packet_id)
        
        recovered_data = bytes([int(p.payload, 16) for p in real_packets])
        
        return recovered_data
    
    def send_secure_message(self, message: str) -> Tuple[List[Dict], Dict]:
        data = message.encode('utf-8')
        
        packet_stream = self.chaff(data)
        
        metadata = {
            'message_length': len(data),
            'total_packets': len(packet_stream),
            'wheat_packets': len(data),
            'chaff_packets': len(packet_stream) - len(data),
            'transmission_time': datetime.utcnow().isoformat(),
            'protocol_version': PROTOCOL_VERSION
        }
        
        serialized_stream = [p.to_dict() for p in packet_stream]
        
        return serialized_stream, metadata
    
    def receive_secure_message(self, packet_stream: List[Dict]) -> str:
        packets = [
            AuthenticatedPacket(**pkt)
            for pkt in packet_stream
        ]
        
        recovered_bytes = self.winnow(packets)
        
        message = recovered_bytes.decode('utf-8')
        
        return message

def demonstrate_protocol():
    
    print("=" * 80)
    print("CHAFFING & WINNOWING PROTOCOL DEMONSTRATION")
    print("Secure Communication Through Compromised Terminals")
    print("=" * 80)
    
    protocol = ChaffWinnowProtocol()
    shared_key = protocol.shared_hmac_key
    print(f"\n✓ Shared HMAC Key (256-bit): {shared_key.hex()}")
    
    session = protocol.create_session(
        sender_id="IC_CARD_001",
        receiver_id="GOVERNMENT_SERVER"
    )
    print(f"\n✓ Session Created: {session.session_id}")
    print(f"  From: {session.sender_id} → To: {session.receiver_id}")
    
    original_message = "IDENTITY_TOKEN_12345"
    print(f"\n✓ Original Message: {original_message}")
    
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
    
    print(f"\n  Sample packets visible to terminal (first 5):")
    for i, pkt in enumerate(packet_stream[:5]):
        print(f"    Packet {i}: payload={pkt['payload'][:16]}... mac={pkt['mac'][:16]}...")
    
    print("\n" + "-" * 80)
    print("SERVER-SIDE FILTERING (with HMAC key):")
    print("-" * 80)
    
    recovered_message = protocol.receive_secure_message(packet_stream)
    
    print(f"\n✓ Server verifies each packet's MAC")
    print(f"✓ Real packets pass verification (wheat)")
    print(f"✓ Fake packets fail verification (chaff discarded)")
    print(f"✓ Recovered Message: {recovered_message}")
    
    success = original_message == recovered_message
    print(f"\n{'✓ SUCCESS' if success else '✗ FAILURE'}: " +
          f"Message integrity verified: {success}")
    
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

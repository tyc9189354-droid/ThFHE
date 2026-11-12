from dataclasses import dataclass

@dataclass
class CommStats:
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    messages_sent: int = 0
    messages_received: int = 0

    def reset(self):
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
        self.messages_sent = 0
        self.messages_received = 0

    def record_send(self, size_bytes: int):
        self.total_bytes_sent += size_bytes
        self.messages_sent += 1

    def record_receive(self, size_bytes: int):
        self.total_bytes_received += size_bytes
        self.messages_received += 1

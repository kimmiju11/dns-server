import socket
import struct
import threading
from typing import Dict, List, Tuple

class DNSServer:
    def __init__(self, host='localhost', port=53):
        self.host = host
        self.port = port
        self.records: Dict[str, str] = {
            'example.com': '192.168.1.1',
            'test.com': '192.168.1.2',
            'localhost': '127.0.0.1'
        }
        
    def add_record(self, domain: str, ip: str):
        """DNS 레코드 추가"""
        self.records[domain] = ip
        
    def parse_dns_query(self, data: bytes) -> Tuple[str, int]:
        """DNS 쿼리 파싱"""
        # DNS 헤더 건너뛰기 (12바이트)
        query_start = 12
        
        # 도메인 이름 파싱
        domain_parts = []
        pos = query_start
        
        while pos < len(data):
            length = data[pos]
            if length == 0:
                break
            pos += 1
            domain_parts.append(data[pos:pos+length].decode('utf-8'))
            pos += length
            
        domain = '.'.join(domain_parts)
        
        # 쿼리 타입 (A 레코드는 1)
        query_type = struct.unpack('!H', data[pos+1:pos+3])[0]
        
        return domain, query_type
        
    def build_dns_response(self, query_data: bytes, domain: str, ip: str) -> bytes:
        """DNS 응답 생성"""
        # 원본 쿼리의 ID 추출
        transaction_id = query_data[:2]
        
        # DNS 헤더 구성
        flags = struct.pack('!H', 0x8180)  # 표준 응답
        questions = struct.pack('!H', 1)    # 1개 질문
        answers = struct.pack('!H', 1)      # 1개 답변
        authority = struct.pack('!H', 0)    # 0개 권한
        additional = struct.pack('!H', 0)   # 0개 추가
        
        header = transaction_id + flags + questions + answers + authority + additional
        
        # 질문 섹션 (원본 쿼리에서 복사)
        question_section = query_data[12:]
        
        # 답변 섹션 구성
        # 도메인 이름 압축 (0xC00C는 오프셋 12를 가리킴)
        name_pointer = struct.pack('!H', 0xC00C)
        record_type = struct.pack('!H', 1)      # A 레코드
        record_class = struct.pack('!H', 1)     # IN 클래스
        ttl = struct.pack('!I', 300)            # TTL 300초
        data_length = struct.pack('!H', 4)      # IPv4 주소 길이
        
        # IP 주소를 바이너리로 변환
        ip_bytes = socket.inet_aton(ip)
        
        answer_section = name_pointer + record_type + record_class + ttl + data_length + ip_bytes
        
        return header + question_section + answer_section
        
    def handle_query(self, data: bytes, addr: Tuple[str, int], sock: socket.socket):
        """DNS 쿼리 처리"""
        try:
            domain, query_type = self.parse_dns_query(data)
            print(f"Query from {addr}: {domain} (type: {query_type})")
            
            if query_type == 1 and domain in self.records:  # A 레코드 쿼리
                ip = self.records[domain]
                response = self.build_dns_response(data, domain, ip)
                sock.sendto(response, addr)
                print(f"Responded: {domain} -> {ip}")
            else:
                print(f"No record found for {domain}")
                
        except Exception as e:
            print(f"Error handling query: {e}")
            
    def start(self):
        """DNS 서버 시작"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            sock.bind((self.host, self.port))
            print(f"DNS Server started on {self.host}:{self.port}")
            
            while True:
                data, addr = sock.recvfrom(512)
                # 각 쿼리를 별도 스레드에서 처리
                thread = threading.Thread(
                    target=self.handle_query, 
                    args=(data, addr, sock)
                )
                thread.daemon = True
                thread.start()
                
        except PermissionError:
            print("Permission denied. Try running with sudo or use port > 1024")
        except KeyboardInterrupt:
            print("\nShutting down DNS server...")
        finally:
            sock.close()

if __name__ == "__main__":
    # 포트 53은 root 권한이 필요하므로 테스트용으로 5353 사용
    server = DNSServer(host='localhost', port=5353)
    
    # 추가 레코드 등록
    server.add_record('mysite.local', '192.168.1.100')
    server.add_record('api.local', '192.168.1.101')
    
    server.start()
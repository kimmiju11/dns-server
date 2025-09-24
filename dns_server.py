import socket
import os
import signal
import sys

# 1. 서버 기본 세팅 (환경변수로 설정 가능)
HOST = os.getenv("DNS_HOST", "0.0.0.0")  # Docker에서는 0.0.0.0으로 바인딩
PORT = int(os.getenv("DNS_PORT", "5353"))

# 도메인별 IP 매핑
DOMAIN_RECORDS = {
    "mytest.local": "192.168.1.100",
    "api.local": "192.168.1.101", 
    "web.local": "10.0.0.50",
    "db.local": "10.0.0.51",
    "mail.local": "10.0.0.52",
    "test.com": "1.2.3.4",
    "example.com": "5.6.7.8"
}

def parse_domain_from_dns(data):
    """DNS 패킷에서 도메인 이름 추출"""
    try:
        pos = 12  # DNS 헤더 이후부터 시작
        domain_parts = []
        
        print(f"    Debug: Starting domain parse at pos {pos}")
        
        while pos < len(data):
            length = data[pos]
            print(f"    Debug: Length byte at pos {pos}: {length}")
            
            if length == 0:  # 도메인 끝
                print("    Debug: Found end of domain")
                break
            
            if length > 63:  # DNS 라벨은 최대 63바이트
                print(f"    Debug: Invalid length {length}, might be compression pointer")
                break
                
            pos += 1
            if pos + length > len(data):
                print("    Debug: Length exceeds data size")
                break
                
            part = data[pos:pos+length].decode('utf-8')
            print(f"    Debug: Domain part: '{part}'")
            domain_parts.append(part)
            pos += length
            
        result = '.'.join(domain_parts)
        print(f"    Debug: Final domain: '{result}'")
        return result
    except Exception as e:
        print(f"    Debug: Exception in parse_domain_from_dns: {e}")
        return None

def ip_to_bytes(ip_str):
    """IP 문자열을 4바이트로 변환"""
    return socket.inet_aton(ip_str)

def build_dns_response(data, queried_domain):
    # 요청 파싱
    transaction_id = data[:2]   # 클라이언트 요청 ID 그대로 반환
    flags = b"\x81\x80"         # 응답 플래그 (표준 응답, 권한 있음)
    qdcount = b"\x00\x01"       # 질문 수 = 1
    ancount = b"\x00\x01"       # 답변 수 = 1
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"

    header = transaction_id + flags + qdcount + ancount + nscount + arcount

    # 질문 섹션 그대로 복사
    question = data[12:]

    # 도메인에 따른 IP 결정
    target_ip = DOMAIN_RECORDS.get(queried_domain, "127.0.0.1")  # 기본값은 127.0.0.1

    # 응답 섹션 - IP가 동적으로 변경됨
    answer_name = b"\xc0\x0c"           # 이름 압축 (포인터: offset 12)
    answer_type = b"\x00\x01"           # Type A
    answer_class = b"\x00\x01"          # IN (Internet)
    ttl = b"\x00\x00\x00\x3c"           # TTL 60초
    rdlength = b"\x00\x04"              # IPv4 = 4바이트
    rdata = ip_to_bytes(target_ip)      # IP 동적 변경!

    answer = answer_name + answer_type + answer_class + ttl + rdlength + rdata

    return header + question + answer

def signal_handler(sig, frame):
    """Graceful shutdown"""
    print("\n[*] Shutting down DNS server...")
    sys.exit(0)

def main():
    # 신호 핸들러 등록
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind((HOST, PORT))
        print(f"[*] DNS Server listening on {HOST}:{PORT}")
        print(f"[*] Configured domains:")
        for domain, ip in DOMAIN_RECORDS.items():
            print(f"    {domain} -> {ip}")

        while True:
            data, addr = sock.recvfrom(512)  # DNS 패킷 최대 크기
            print(f"[+] Query from {addr}")
            
            # 디버깅: 패킷 내용 확인
            print(f"    Raw data length: {len(data)}")
            print(f"    Raw data (hex): {data[:50].hex()}")
            
            # 도메인 파싱
            queried_domain = parse_domain_from_dns(data)
            print(f"    Queried domain: {queried_domain}")

            # 도메인 매칭 및 응답
            if queried_domain:
                if queried_domain in DOMAIN_RECORDS:
                    target_ip = DOMAIN_RECORDS[queried_domain]
                    response = build_dns_response(data, queried_domain)
                    sock.sendto(response, addr)
                    print(f"    -> ✅ Responded: {queried_domain} -> {target_ip}")
                else:
                    # 등록되지 않은 도메인도 기본 IP로 응답
                    response = build_dns_response(data, queried_domain)
                    sock.sendto(response, addr)
                    print(f"    -> 🔧 Default response: {queried_domain} -> 127.0.0.1")
            else:
                print(f"    -> ❌ Invalid domain query")
                
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
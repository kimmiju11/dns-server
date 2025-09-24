FROM python:3.11-slim

# 작업 디렉토리 설정
WORKDIR /app

# DNS 서버 파일 복사
COPY dns_server.py .

# 포트 노출 (UDP 포트)
EXPOSE 5353/udp

# DNS 서버 실행
CMD ["python", "dns_server.py"]
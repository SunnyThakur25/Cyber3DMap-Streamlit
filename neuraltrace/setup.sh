#!/bin/bash

# NeuralTrace Setup Script
echo "[*] Setting up NeuralTrace..."

# Update system
sudo apt update
sudo apt install -y git python3 python3-pip postgresql postgresql-contrib tor libpcap-dev zeek

# Clone repository
git clone https://github.com/redteam/neuraltrace.git
cd neuraltrace

# Install Python dependencies
pip3 install -r requirements.txt

# Set up PostgreSQL
sudo -u postgres psql -c "CREATE DATABASE neuraltrace;"
sudo -u postgres psql -c "CREATE USER neuraltrace WITH PASSWORD 'securepass';"
sudo -u postgres psql -c "ALTER ROLE neuraltrace SET client_encoding TO 'utf8';"
sudo -u postgres psql -c "ALTER ROLE neuraltrace SET default_transaction_isolation TO 'read committed';"
sudo -u postgres psql -c "ALTER ROLE neuraltrace SET timezone TO 'UTC';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE neuraltrace TO neuraltrace;"

# Configure Zeek
sudo zeekctl install
sudo zeekctl deploy

# Create .env
cat << EOF > .env
XAI_API_KEY=your_xai_key
X_API_KEY=your_x_key
WHOIS_API_KEY=your_whoisxml_key
BRIGHTDATA_AUTH=your_brightdata_auth
DB_URL=postgresql://neuraltrace:securepass@localhost:5432/neuraltrace
AWS_ACCESS_KEY=your_aws_access_key
AWS_SECRET_KEY=your_aws_secret_key
AWS_S3_BUCKET=your_s3_bucket
DATASET_PATH=/data/cicids2017.csv
EOF

# Create and encrypt config.json
cat << EOF > config.json
{
  "XAI_API_KEY": "$XAI_API_KEY",
  "X_API_KEY": "$X_API_KEY",
  "WHOIS_API_KEY": "$WHOIS_API_KEY",
  "BRIGHTDATA_AUTH": "$BRIGHTDATA_AUTH",
  "DB_URL": "$DB_URL",
  "AWS_ACCESS_KEY": "$AWS_ACCESS_KEY",
  "AWS_SECRET_KEY": "$AWS_SECRET_KEY",
  "AWS_S3_BUCKET": "$AWS_S3_BUCKET",
  "DATASET_PATH": "$DATASET_PATH"
}
EOF

python3 -c "from cryptography.fernet import Fernet; key = Fernet.generate_key(); f = Fernet(key); with open('config.json', 'rb') as f_in, open('config.json.enc', 'wb') as f_out: f_out.write(f.encrypt(f_in.read())); with open('config.key', 'wb') as k: k.write(key)"
rm config.json

# Initialize database
python3 -m neuraltrace.cli --init-db

# Start Tor
sudo service tor start

echo "[*] Setup complete! Edit .env with your API keys."
echo "[*] Run: python3 -m neuraltrace.cli --interface <interface> --count <packets>"
echo "[*] Dashboard: streamlit run neuraltrace/dashboard.py"
echo "[*] API: uvicorn neuraltrace.api.log_correlator:app --host 0.0.0.0 --port 8000"
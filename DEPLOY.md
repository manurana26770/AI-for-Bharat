# Deployment Guide for AWS (Free Tier)

This guide will help you deploy the Varutri Honeypot application using **AWS EC2 (Free Tier)**.

## Prerequisites
- An [AWS Account](https://aws.amazon.com/) (eligible for Free Tier).
- A [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) account (Free Cluster).
    - *Note: We recommend using MongoDB Atlas instead of running MongoDB on the EC2 instance because the free tier EC2 instance (t2.micro) has limited RAM (1GB).*
- [Git](https://git-scm.com/) installed locally.

---

## Step 1: Launch an AWS EC2 Instance

1.  **Log in to AWS Console** and navigate to **EC2**.
2.  Click **Launch Instance**.
3.  **Name**: `Varutri-Honeypot`.
4.  **AMI (OS)**: Select **Ubuntu** (Ubuntu Server 24.04 LTS or 22.04 LTS).
5.  **Instance Type**: Select **t2.micro** (or `t3.micro` if eligible). This is free tier eligible.
6.  **Key Pair**: Create a new key pair (e.g., `honeypot-key`). **Download the .pem file** and keep it safe.
7.  **Network Settings**:
    - Check **Allow SSH traffic from**. Select "My IP" for security, or "Anywhere" if you need to access from multiple places.
    - Check **Allow HTTP traffic from the internet**.
    - Check **Allow HTTPS traffic from the internet**.
8.  **Configure Storage**: The default 8GB gp2/gp3 is fine.
9.  Click **Launch Instance**.

---

## Step 2: Configure Security Group (Firewall)

1.  In the EC2 Dashboard, go to **Instances**.
2.  Click on your new instance ID.
3.  Click the **Security** tab -> Click the **Security Group** (e.g., `sg-xxxx`).
4.  Click **Edit inbound rules**.
5.  Address the following rules:
    - **SSH** (Port 22): source `Anywhere` or `My IP` (Already there).
    - **Custom TCP** (Port 8080): source `Anywhere` (IPv4 `0.0.0.0/0`). *This is for your API.*
6.  Click **Save rules**.

---

## Step 3: Deployment

1.  **Connect to your instance**:
    - Open your terminal (or PowerShell on Windows).
    - Locate your `.pem` key file.
    - Run:
      ```bash
      # Provide read-only permission to key (Linux/Mac only, skip on Windows)
      chmod 400 honeypot-key.pem

      # Connect
      ssh -i "path/to/honeypot-key.pem" ubuntu@<YOUR_EC2_PUBLIC_IP>
      ```

2.  **Install Docker & Git on Server**:
    Run these commands inside the SSH session:
    ```bash
    # Update packages
    sudo apt-get update

    # Install Docker
    sudo apt-get install -y docker.io docker-compose-v2 git

    # Start Docker
    sudo systemctl start docker
    sudo systemctl enable docker

    # Add user to docker group (avoids using sudo for docker commands)
    sudo usermod -aG docker $USER
    ```
    *Exit the SSH session (`exit`) and log in again for the group change to take effect.*

3.  **Clone the Repository**:
    ```bash
    git clone https://github.com/YOUR_GITHUB_USER/Varutri-Honeypot.git
    cd Varutri-Honeypot
    ```

4.  **Configure Environment Variables**:
    Create the `.env` file on the server.
    ```bash
    nano .env
    ```
    Paste the contents of your local `.env` file (ensure you have your **MongoDB Atlas Connection String** and **API Keys** ready).
    
    *Press `Ctrl+X`, then `Y`, then `Enter` to save.*

5.  **Start the Application**:
    ```bash
    docker compose up -d --build
    ```

---

## Step 4: Verify Deployment

1.  Wait a minute for the build to finish and the app to start.
2.  Check if it's running:
    ```bash
    docker compose ps
    docker compose logs -f
    ```
3.  Test via Browser or Postman:
    `http://<YOUR_EC2_PUBLIC_IP>:8080/api/v1/health`

---

## Maintenance

- **Update Code**:
  ```bash
  git pull origin main
  docker compose up -d --build
  ```
- **View Logs**:
  ```bash
  docker compose logs -f
  ```

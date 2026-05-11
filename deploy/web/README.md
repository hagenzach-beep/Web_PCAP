# PowerScale Analyzer - Web Deployment

This package contains configuration for deploying the PowerScale PCAP & Log Analyzer to web platforms.

## Streamlit Cloud Deployment (Recommended)

Streamlit Cloud is the easiest way to deploy your app to the web.

### Prerequisites

- A GitHub account
- Your code pushed to a GitHub repository
- A Streamlit Cloud account (free at https://streamlit.io/cloud)

### Deployment Steps

1. **Push your code to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/yourusername/powerscale-analyzer.git
   git push -u origin main
   ```

2. **Sign up for Streamlit Cloud:**
   - Go to https://streamlit.io/cloud
   - Sign in with your GitHub account

3. **Deploy your app:**
   - Click "New app"
   - Select your repository
   - Select the main branch
   - Set main file path to `app.py`
   - Click "Deploy"

4. **Configuration (optional):**
   Add a `.streamlit/config.toml` file to customize your deployment:
   ```toml
   [server]
   port = 8501
   headless = true
   enableCORS = false
   enableXsrfProtection = false
   
   [theme]
   primaryColor = "#F63366"
   backgroundColor = "#FFFFFF"
   ```

### Important Notes for Web Deployment

- **TShark Availability**: TShark may not be available in all cloud environments. You may need to:
  - Use a container-based deployment (Docker)
  - Or modify the app to handle missing TShark gracefully

- **File Upload Limits**: Streamlit Cloud has file upload limits. For large PCAP files:
  - Consider using cloud storage (S3, GCS, Azure Blob)
  - Or implement chunked upload

- **Knowledge Base**: Ensure `knowledge.db` is included in your repository or accessible from the cloud environment

- **Persistent Storage**: Streamlit Cloud doesn't provide persistent storage. Uploaded files will be lost between sessions.

## Docker Cloud Deployment

For more control over the deployment environment, use Docker.

### Docker Hub

1. **Build and push to Docker Hub:**
   ```bash
   docker build -t yourusername/powerscale-analyzer:latest .
   docker push yourusername/powerscale-analyzer:latest
   ```

2. **Deploy to cloud platforms:**
   - **AWS ECS**: Use the Docker image in your ECS task definition
   - **Google Cloud Run**: Deploy the Docker image
   - **Azure Container Instances**: Deploy the Docker image
   - **Heroku**: Use the Docker image with Heroku Container Registry

### Kubernetes Deployment

Create a `k8s-deployment.yaml` file:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: powerscale-analyzer
spec:
  replicas: 1
  selector:
    matchLabels:
      app: powerscale-analyzer
  template:
    metadata:
      labels:
        app: powerscale-analyzer
    spec:
      containers:
      - name: powerscale-analyzer
        image: yourusername/powerscale-analyzer:latest
        ports:
        - containerPort: 8501
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
---
apiVersion: v1
kind: Service
metadata:
  name: powerscale-analyzer-service
spec:
  selector:
    app: powerscale-analyzer
  ports:
  - port: 80
    targetPort: 8501
  type: LoadBalancer
```

Deploy to Kubernetes:
```bash
kubectl apply -f k8s-deployment.yaml
```

## Heroku Deployment

1. **Create a Heroku app:**
   ```bash
   heroku create your-app-name
   ```

2. **Create a Procfile:**
   ```
   web: streamlit run app.py --server.port=$PORT
   ```

3. **Deploy:**
   ```bash
   git push heroku main
   ```

## AWS Deployment

### AWS App Runner

1. **Push your Docker image to Amazon ECR**
2. **Create an App Runner service** pointing to your ECR image
3. **Configure environment variables** as needed

### AWS Elastic Beanstalk

1. **Create a `requirements.txt`** (already included)
2. **Create a `.ebextensions/python.config`**:
   ```yaml
   commands:
     01_install_tshark:
       command: yum install -y wireshark
   packages:
     yum:
       wireshark: []
   ```

3. **Deploy using EB CLI:**
   ```bash
   eb init
   eb create
   ```

## Security Considerations

- **Authentication**: Add authentication for production deployments
- **HTTPS**: Enable HTTPS for all web deployments
- **Rate Limiting**: Implement rate limiting to prevent abuse
- **Input Validation**: Validate all user inputs
- **File Size Limits**: Set appropriate file upload limits

## Monitoring

- **Streamlit Cloud**: Built-in monitoring available
- **Docker**: Use container monitoring tools (Prometheus, Grafana)
- **Kubernetes**: Use Kubernetes monitoring tools
- **Cloud Platforms**: Use platform-specific monitoring services

## Troubleshooting

### TShark not found in cloud environment
- Use a Docker image that includes TShark
- Or implement fallback logic in the app

### Memory issues with large PCAP files
- Increase memory limits in your deployment configuration
- Implement file streaming instead of loading entire files
- Add file size validation

### Slow performance
- Use horizontal scaling (multiple instances)
- Implement caching
- Optimize TShark queries

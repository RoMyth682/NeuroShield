FROM python:3.10

# A05: Running as root (should use a non-root user)
USER root

# A05: Using ADD instead of COPY (ADD can fetch remote URLs)
ADD requirements.txt /app/requirements.txt

WORKDIR /app
RUN pip install -r requirements.txt

COPY . .

# No HEALTHCHECK defined
CMD ["python", "app.py"]

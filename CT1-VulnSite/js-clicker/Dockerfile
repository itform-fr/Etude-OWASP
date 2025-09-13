# Use an official Node.js image based on Alpine
FROM node:18-alpine

# Set the working directory inside the container
WORKDIR /app

# Install dependencies required for Chromium to run
RUN apk update && apk add --no-cache \
    bash \
    curl \
    ca-certificates \
    libx11 \
    libxcomposite \
    libxrandr \
    libxi \
    libatk-1.0 \
    nss \
    ttf-freefont \
    chromium \
    fontconfig \
    harfbuzz \
    freetype \
    libstdc++

# Install Puppeteer
RUN npm install puppeteer

# Copy your Puppeteer script into the container
COPY ./click.js /app/click.js

# Set environment variable for headless Chrome
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

# Command to run your script when the container starts
CMD ["node", "/app/click.js"]


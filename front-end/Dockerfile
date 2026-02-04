FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
# For development (Vite), we use the dev command
CMD ["npm", "run", "dev", "--", "--host"]
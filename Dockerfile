FROM node:22-alpine
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY *.html ./
COPY bin ./bin
COPY docs ./docs
COPY mitre-attack ./mitre-attack
COPY playbooks ./playbooks
COPY server ./server
COPY tools ./tools
COPY Xss ./Xss

ENV NODE_ENV=production
EXPOSE 3847
CMD ["node", "server/index.js"]

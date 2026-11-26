FROM node:22-alpine AS ui-build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY server/modules/external-tools/standalone/news-verifier/package.json \
  server/modules/external-tools/standalone/news-verifier/package-lock.json \
  ./server/modules/external-tools/standalone/news-verifier/
RUN npm --prefix server/modules/external-tools/standalone/news-verifier ci

COPY frontend ./frontend
COPY public ./public
COPY scripts/clean-react-ui-assets.mjs ./scripts/clean-react-ui-assets.mjs
COPY server/modules/external-tools/standalone/news-verifier \
  ./server/modules/external-tools/standalone/news-verifier
RUN npm run ui:build
RUN npm --prefix server/modules/external-tools/standalone/news-verifier run build

FROM node:22-alpine
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY --from=ui-build /app/public ./public
COPY bin ./bin
COPY docs ./docs
COPY mitre-attack ./mitre-attack
COPY playbooks ./playbooks
COPY bridge ./bridge
COPY engines ./engines
COPY server ./server
COPY --from=ui-build /app/server/modules/external-tools/standalone/news-verifier/dist \
  ./server/modules/external-tools/standalone/news-verifier/dist
COPY tools ./tools
COPY Xss ./Xss

ENV NODE_ENV=production
ENV HOST=0.0.0.0
EXPOSE 3847
CMD ["node", "server/index.js"]

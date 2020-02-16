FROM node:10
WORKDIR /usr/src/app
COPY . .
RUN npm install
EXPOSE 8088
CMD [ "node", "server.js" ]

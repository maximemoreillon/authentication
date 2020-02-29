FROM node:10
WORKDIR /usr/src/app
COPY . .
RUN npm install
EXPOSE 7088
CMD [ "node", "server.js" ]

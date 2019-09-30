# Build stage

FROM node:alpine 

WORKDIR /nav-app/

# copy over needed files
COPY . ./

# install packages and build 
RUN npm install --unsafe-perm

EXPOSE 4200

CMD npm start

# docker run --mount type=bind,source="$(pwd)/nav_layer_playbook.json",target=/nav-app/src/assets/playbook.json -dp 4200:4200 so-navigator:1.0

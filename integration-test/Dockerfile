FROM mcr.microsoft.com/playwright:bionic

WORKDIR /app

COPY package.json .

RUN yarn install

COPY . .

CMD ["yarn", "test"]
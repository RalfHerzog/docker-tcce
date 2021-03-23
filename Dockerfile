FROM ruby:2.6-alpine

WORKDIR /usr/src/app

COPY Gemfile Gemfile.lock ./
RUN bundle install

COPY . .

VOLUME ["/export"]

CMD ["ruby", "main.rb"]
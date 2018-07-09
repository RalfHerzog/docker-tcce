FROM ruby:2.5-alpine

WORKDIR /usr/src/app

COPY Gemfile Gemfile.lock ./
RUN bundle install

COPY . .

VOLUME ["/export"]

CMD ["ruby", "main.rb"]
FROM python:3.10.10-slim-bullseye
COPY . /usr/app/
WORKDIR /usr/app/
RUN pip install -r requirements.txt
EXPOSE 5000
USER 12345
CMD python navie_bias.py
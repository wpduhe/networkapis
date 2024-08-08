FROM hca-docker-innersource.repos.medcity.net/containers/base/python-3.8

ARG PORT=8080

# install dependencies

# COPY ./src/requirements.txt .

RUN pip3 install --upgrade pip
RUN pip3 install --upgrade setuptools
RUN --mount=type=secret,id=nexuscreds --mount=type=bind,source=./src/requirements.txt,target=./requirements.txt \
  pip3 install --no-cache-dir -r ./requirements.txt --no-deps \
  --extra-index-url=https://$( cat /run/secrets/nexuscreds )@repos.medcity.net/repository/hcanetworkservicespypi/simple

COPY src /opt/app/
COPY --chmod=0755 entrypoint.sh loggingconfig.json .

WORKDIR /opt/app/src

# This form allows for graceful shutdown of app, killing background threads
ENTRYPOINT [ "uvicorn","main:app","--port=8080","--host=0.0.0.0" ]
# ENTRYPOINT [ "uvicorn","main:app","--port=8080","--host=0.0.0.0","--log-config=/opt/app/loggingconfig.json" ]
# ENTRYPOINT [ "/opt/app/entrypoint.sh" ]
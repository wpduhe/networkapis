FROM hca-docker-innersource.repos.medcity.net/containers/base/python-3.8

# token expiration can be overridden from docker run
ENV TOKEN_EXPIRATION_MINUTES 10080

# these could also be overridden, but probably not a good reason to do so. These
# two are required by the nm_jwt_oauth_plugin plugin.
ENV ROLE_MAPPER "app.role_mapper.role_mapper"
ENV SCOPE_DEFS "app.role_mapper.get_scopes"

ARG PORT=8080

WORKDIR /opt/app

# install dependencies

COPY src/requirements.txt .

RUN pip3 install --upgrade pip
RUN pip3 install --upgrade setuptools
RUN --mount=type=secret,id=nexuscreds \
  pip3 install --no-cache-dir -r requirements.txt --no-deps \
  --extra-index-url=https://$( cat /run/secrets/nexuscreds)@nexus.hca.corpad.net/repository/hcanetworkservicespypi/simple \
  --trusted-host=nexus.hca.corpad.net

COPY src /opt/app/
COPY entrypoint.sh loggingconfig.json .

WORKDIR /opt/app/src

# This form allows for graceful shutdown of app, killing background threads
ENTRYPOINT [ "/opt/app/entrypoint.sh" ]

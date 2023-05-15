FROM postgres:latest

 
ENV POSTGRES_USER postgres
ENV POSTGRES_PASSWORD Ebosdev1
ENV POSTGRES_DB EO4EU-Main-DB

ENV PGDATA /var/lib/postgresql/data

RUN mkdir -p $PGDATA && chown -R postgres:postgres $PGDATA

VOLUME $PGDATA

COPY ./script/test.sql /docker-entrypoint-initdb.d/
COPY delay_script.sh /docker-entrypoint-initdb.d/
COPY backuptest.dump /docker-entrypoint-initdb.d/ 
COPY test.dump /docker-entrypoint-initdb.d/ 

RUN chmod +x /docker-entrypoint-initdb.d/delay_script.sh
 

#COPY insert_commands.sql /docker-entrypoint-initdb.d/

EXPOSE 5432
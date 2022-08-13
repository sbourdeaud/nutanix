FROM python:3.10.0-alpine3.14

WORKDIR /~

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "./AddS3Data.py" ]

# MANDATORY: used to specify the objectstore url
ENV ENDPOINT_URL='http://127.0.0.1'
# MANDATORY: used to specify the access key for the objectstore 
ENV ACCESS_KEY=''
# MANDATORY: used to specify the secret key for the objectstore 
ENV SECRET_KEY=''
# MANDATORY: used to specify the bucket name
ENV BUCKET=''

#used to specify the minimum and maximum size of random data to generate. 
#the script will randomly select a size in that range. 
#the values indicated are default when nothing else is specified.
ENV FILE_SIZE_MIN_BYTES='1024'
ENV FILE_SIZE_MAX_BYTES='524288000'

#used to specify the minimum and maximum count of objects which will use the same seed for filename.
#the script processes random data in batch using that seed, then loops again with a random number of files with another seed. 
#the script will randomly select a size in that range. 
#the values indicated are default when nothing else is specified.
ENV FILE_COUNT_MIN='1'
ENV FILE_COUNT_MAX='50'
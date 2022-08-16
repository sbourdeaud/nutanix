from datetime import datetime
from botocore.exceptions import ClientError
import boto3, os, time, sys, random, string



class bcolors:
    OK = '\033[92m' #GREEN
    WARNING = '\033[93m' #YELLOW
    FAIL = '\033[91m' #RED
    RESET = '\033[0m' #RESET COLOR   

def generate_random_bin_file(filename,size):
    """
    generate binary file with the specified size in bytes
    :param filename: the filename
    :param size: the size in bytes
    :return:void
    """
    import os 
    with open('%s'%filename, 'wb') as fout:
        fout.write(os.urandom(size))
    print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Random binary file {filename} with size {size} generated ok{bcolors.RESET}")
    pass

def main():
    """Main entry point"""

    print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Getting environment variables...{bcolors.RESET}")
    endpoint_url = str(os.getenv("ENDPOINT_URL", "http://127.0.0.1"))
    access_key = str(os.getenv("ACCESS_KEY", ""))
    secret_key = str(os.getenv("SECRET_KEY", ""))
    bucket = str(os.getenv("BUCKET", ""))
    file_size_min_bytes = int(os.getenv("FILE_SIZE_MIN_BYTES", "1024"))
    file_size_max_bytes = int(os.getenv("FILE_SIZE_MAX_BYTES", "5242880"))
    file_count_min = int(os.getenv("FILE_COUNT_MIN", "1"))
    file_count_max = int(os.getenv("FILE_COUNT_MAX", "50"))
    upload_retries_count = 24
    upload_retries_delay = 5

    #*main loop here
    
    while True:
        
        file_count = random.randint(file_count_min,file_count_max)
        #create 15 random characters string for filename seed
        my_string = string.ascii_lowercase
        my_characters = ''.join(random.choice(my_string) for i in range(15))
        
        #! creates files instead of processing random data from memory
        ''' #*create random data/files of random size range
        loop_count = file_count
        while loop_count > 0:
            file_size = random.randint(file_size_min_bytes,file_size_max_bytes)
            filename = f"{my_characters}_{loop_count}.dat"
            generate_random_bin_file(filename,file_size)
            loop_count -= 1 '''
        
        #*upload files
        loop_count = file_count
        while loop_count > 0:
            retries = upload_retries_count
            filename = f"{my_characters}_{loop_count}.dat"
            print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Processing file {filename}...{bcolors.RESET}")
            while retries > 0:
                try: 
                    #*connect to s3
                    print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Opening session to {endpoint_url}{bcolors.RESET}")
                    session = boto3.session.Session()
                    s3c = session.client(
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_key,
                        endpoint_url=endpoint_url,
                        service_name="s3",
                        use_ssl=False,
                    )

                    #check if bucket exists
                    try:
                        s3c.head_bucket(Bucket=bucket)
                        print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Bucket exists : {bucket}{bcolors.RESET}")
                    except ClientError:
                        print(f"{bcolors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Bucket {bucket} does not exist.  "
                            + f"Attempting to create bucket ...{bcolors.RESET}")
                        try:
                            s3c.create_bucket(Bucket=bucket)
                        except Exception as err:
                            print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] An exception occurred while creating the "
                                + f"{bucket} bucket.  "
                                + f"Details: {err}{bcolors.RESET}")
                            retries -= 1
                            if retries > 0:
                                print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Waiting for {upload_retries_delay} seconds before retrying... ({retries} retries left){bcolors.RESET}")
                                time.sleep(upload_retries_delay)
                            continue

                    data_size = random.randint(file_size_min_bytes,file_size_max_bytes)
                    key=filename
                    # create file handle and upload the file to Objects endpoint.
                    print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Uploading file {filename} with size {data_size} bytes as object "
                        + f"{key} in bucket {bucket} ...{bcolors.RESET}")
                    s3c.put_object(Bucket=bucket,
                                Key=key,
                                Body=os.urandom(data_size))
                    break
                    #! optionally verify file has been uploaded and dump details about the object
                    ''' # verify if file is uploaded
                    print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Checking if {key} exists ...{bcolors.RESET}")
                    response = s3c.head_object(Bucket=bucket,
                                            Key=key)
                    print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Head Object Response : {response}{bcolors.RESET}") '''
                except s3c.exceptions.NoSuchBucket:
                    print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] The {bucket} bucket does not exist.  "
                        + f"Aborting ...{bcolors.RESET}")
                    retries -= 1
                    if retries > 0:
                        print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Waiting for {upload_retries_delay} seconds before retrying... ({retries} retries left){bcolors.RESET}")
                        time.sleep(upload_retries_delay)
                    continue
                except Exception as err:
                    print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] An unexpected exception occurred while attempting "
                        + f"file upload.  Details:")
                    print(f"{err}{bcolors.RESET}")
                    retries -= 1
                    if retries > 0:
                        print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Waiting for {upload_retries_delay} seconds before retrying... ({retries} retries left){bcolors.RESET}")
                        time.sleep(upload_retries_delay)
                    continue
            loop_count -= 1
        
        #! deletes created files
        ''' #*remove files
        loop_count = file_count
        while loop_count > 0:
            filename = f"{my_characters}_{loop_count}.dat"
            os.remove(filename)
            print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Removed file {filename}{bcolors.RESET}")
            loop_count -= 1'''
        
if __name__ == "__main__":
    main()
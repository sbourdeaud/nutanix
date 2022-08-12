import random
from datetime import datetime

class bcolors:
    OK = '\033[92m' #GREEN
    WARNING = '\033[93m' #YELLOW
    FAIL = '\033[91m' #RED
    RESET = '\033[0m' #RESET COLOR   


def generate_random_bin_file(filename,size):
    """
    generate big binary file with the specified size in bytes
    :param filename: the filename
    :param size: the size in bytes
    :return:void
    """
    import os 
    with open('%s'%filename, 'wb') as fout:
        fout.write(os.urandom(size)) #1
    print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Random binary file {filename} with size {size} generated ok{bcolors.RESET}")
    pass

if __name__ == '__main__':
    file_count_min = 1
    file_count_max = 10
    file_size_min_bytes = 1024
    file_size_max_bytes = 1024*1024*1024
    
    file_count = random.randint(file_count_min,file_count_max)
    #create 15 random characters string for filename seed
    my_string = string.ascii_lowercase
    my_characters = ''.join(random.choice(my_string) for i in range(15))
    while file_count > 0:
        file_size = random.randint(file_size_min_bytes,file_size_max_bytes)
        filename = f"{my_characters}_{file_count}.dat"
        generate_random_bin_file(filename,file_size)
        file_count -= 1
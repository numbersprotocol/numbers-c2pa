from numbers_c2pa import read_c2pa_file

if __name__ == '__main__':
    c2pa_json = read_c2pa_file('examples/numbers-c2pa.png')
    print(c2pa_json)

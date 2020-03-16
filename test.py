from multiprocessing import Pool
from tinydb import where

def test_func(word):
    print(word)

def main():
    words = ['this', 'should', 'work']
    pool = Pool(2)

    test = pool.map(test_func, words)

if __name__ == '__main__':
    main()

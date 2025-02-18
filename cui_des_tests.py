import cui_des
from cui_des import DES, T_DES
import des_tests_subkey as test_subkey
import homework09 as hw9


def run_unit_tests(obj):
    """ Runs unit tests for each function in this module. Prints 'ALL UNIT
        TESTS PASSED' if all of the unit tests were successful. Raises an
        AssertionError if any single unit test fails. """
    
    tests = [
        # Format: (function, [list of arguments], expected output)

        # Add padding tests
        (cui_des._add_padding, [b'CSC428'], b'CSC428\x02\x02'),
        (cui_des._add_padding, [b'TALLMAN'], b'TALLMAN\x01'),
        (cui_des._add_padding, [b'JTALLMAN'], b'JTALLMAN\x08\x08\x08\x08\x08\x08\x08\x08'),

        # Remove padding tests
        (cui_des._rem_padding, [b'CSC428\x02\x02'], b'CSC428'),
        (cui_des._rem_padding, [b'TALLMAN\x01'], b'TALLMAN'),
        (cui_des._rem_padding, [b'JTALLMAN\x08\x08\x08\x08\x08\x08\x08\x08'], b'JTALLMAN'),

        # Bytes to bit array tests
        (cui_des._bytes_to_bit_array, [b'\x00'], [0,0,0,0,0,0,0,0]),
        (cui_des._bytes_to_bit_array, [b'\xA5'], [1,0,1,0,0,1,0,1]),
        (cui_des._bytes_to_bit_array, [b'\xFF'], [1,1,1,1,1,1,1,1]),

        # Bit array to bytes tests
        (cui_des._bit_array_to_bytes, [[0,0,0,0,0,0,0,0]], b'\x00'),
        (cui_des._bit_array_to_bytes, [[1,0,1,0,0,1,0,1]], b'\xA5'),
        (cui_des._bit_array_to_bytes, [[1,1,1,1,1,1,1,1]], b'\xFF'),
        
        # N split Tests
        (cui_des._nsplit, [b'1111222233334444', 4], [b'1111', b'2222', b'3333', b'4444']),
        (cui_des._nsplit, [b'ABCDEFGHIJKLMN', 3], [b'ABC', b'DEF', b'GHI', b'JKL', b'MN']),
        (cui_des._nsplit, [b'THE CODE BOOK BY SINGH', 5], [b'THE C', b'ODE B', b'OOK B', b'Y SIN', b"GH"]),

        # Permute Tests

        # # SBOX
        (des._permute, [['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
                    'q','r','s','t','u','v','w','x','y','z','!','1','2','3','4','5'], cui_des.tables._SBOX_PERM],
                    
                    ['p','g','t','u','2','l','1','q','a','o','w','z','e','r','4','j',
                     'b','h','x','n','5','!','c','i','s','m','3','f','v','k','d','y',]),

        # # INIT
        (des._permute, [['Y','0','U','\'','V','3','I','N','T','3','R','C','3','P','T','3',
                    'D','A','S','U','S','P','I','C','I','0','U','S','C','I','P','H',
                    '3','R','T','3','X','T',',','W','H','I','C','H','Y','0','U','B',
                    '3','L','I','3','V','3','T','0','H','A','V','3','B','3','3','N'], cui_des.tables._INIT_PERMUTATION],
                    
                    ['A','L','I','R','0','A','3','0','3','3','H','3','S','U','C','\'',
                     '3','3','0','T','I','P','P','3','N','0','B','W','H','C','3','N',
                     'H','3','H','3','I','D','T','Y','V','I','C','T','U','S','R','U',
                     'B','V','Y','X','C','S','3','V','3','T','U',',','P','I','T','I',]),

        # FINI
        (des._permute, [['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
                    'Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5',
                    '6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l',
                    '0','1','2','3','4','5','6','7','8','9','0','!','?','*',':',')'], cui_des.tables._FINAL_PERMUTATION],
                    
                    ['d','H','l','P','7','X',')','5','c','G','k','O','6','W',':','4',
                     'b','F','j','N','5','V','*','3','a','E','i','M','4','U','?','2',
                     '9','D','h','L','3','T','!','1','8','C','g','K','2','S','0','0',
                     '7','B','f','J','1','R','9','Z','6','A','e','I','0','Q','8','Y']),

        # EXPAND  
        (des._permute, [['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
                    'Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','!'], cui_des.tables._EXPAND],
                    
                    ['!','A','B','C','D','E','D','E','F','G','H','I','H','I','J','K',
                     'L','M','L','M','N','O','P','Q','P','Q','R','S','T','U','T','U',
                     'V','W','X','Y','X', 'Y', 'Z','0','1','2','1','2','3','4','!','A']),

        # Left shift tests
        (des._lshift, [[1,2,3,4,5], 2], [3,4,5,1,2]),
        (des._lshift, [[5,4,3,2,1], 3], [2,1,5,4,3]),

        # XOR tests
        (des._xor, [[1, 0, 1, 0, 1, 1, 1], [1, 1, 1, 1, 1, 1, 1]], [0, 1, 0, 1, 0, 0, 0]),

        # Generate Subkey tests
        (des._generate_subkeys, [test_subkey.subkey_input], test_subkey.subkey_result),

        # Substitute tests
        (des._substitute, [
            [0,1,1,0,1,1,
            1,1,0,0,1,1,
            1,1,0,0,0,1,
            0,1,0,0,0,0,
            0,1,0,1,0,1,
            1,1,1,0,0,1,
            0,1,1,1,0,0,
            0,1,0,1,0,0]],
         [0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1]),
        
    ]


    print(f'Running {len(tests)} tests...')
    for i, test in enumerate(tests):
        func = test[0]
        args = test[1]
        output = test[2]

        result = func(*args)
        assert result == output, f"❌ Unit test #{i+1} failed: {func.__name__}({args})"    

    
    print('All UNIT TESTS PASSED ✅')



def run_system_tests(des, tdes):

    testsECB = [
        # Regular DES Encryption tests
        (des.encrypt, [b'hello there', b'infosec8'], b'\x13\xc9\xec\x9b9\xee\xa5\x1cLi[\xfe>\x96\xa1\xc7'),
        # Test with class key variable
        (des.encrypt, [b'hello there'], b'\x10W$c\xb0\xe2 \xa2\x95\x0bo\x8fl?\rp'),

        # Decryption tests
        (des.decrypt, [b'\x13\xc9\xec\x9b9\xee\xa5\x1cLi[\xfe>\x96\xa1\xc7', b'infosec8'], b'hello there'),
        # Test with class key variable
        (des.decrypt, [b'\x10W$c\xb0\xe2 \xa2\x95\x0bo\x8fl?\rp'], b'hello there'),

        # Triple DES Encryption tests
        (tdes.encrypt, [b'hello there', b'applejaminfosec8okyeahoh'], b'\xa3\x1e\xa4ZZ\x00\x07=\x17\xfa3\x0c\xb5\x94\x01!'),
        # Test with class key variable
        (tdes.encrypt, [b'hello there'], b"\x0f\xa9\xe2=DG{g\x92\xe7\xeb>'\xd2\xf0%"),

        # Decryption tests
        (tdes.decrypt, [b'\xa3\x1e\xa4ZZ\x00\x07=\x17\xfa3\x0c\xb5\x94\x01!', b'applejaminfosec8okyeahoh'], b'hello there'),
        # Test with class key variable
        (tdes.decrypt, [b"\x0f\xa9\xe2=DG{g\x92\xe7\xeb>'\xd2\xf0%"], b'hello there')
    ]

    testsCBC = [
        # Regular DES Encryption tests
        (des.encrypt, [b'hello there', b'infosec8', b'\x00'*8], b'\x13\xc9\xec\x9b9\xee\xa5\x1c\xae\xf2\xa9\xaf\xc6\x0cS\\'),
    
        # Decryption tests
        (des.decrypt, [hw9.ciphertext2, hw9.secret_key2, hw9.initvector2],
         b'For the word of God is alive and powerful. It is sharper than the sharpest two-edged sword, cutting between soul and spirit, between joint and marrow. It exposes our innermost thoughts and desires. Nothing in all creation is hidden from God. Everything is naked and exposed before his eyes, and he is the one to whom we are accountable.\n\nSo then, since we have a great High Priest who has entered heaven, Jesus the Son of God, let us hold firmly to what we believe. This High Priest of ours understands our weaknesses, for he faced all of the same testings we do, yet he did not sin. So let us come boldly to the throne of our gracious God. There we will receive his mercy, and we will find grace to help us when we need it most.'),

        # Triple DES Encryption tests
        (tdes.encrypt, [b'hello there', b'applejaminfosec8okyeahoh', b'\x01'*8, False], b'\xd0m\x9b\xednX\x8e\x08\xb4\xbfj4\x1e\xbd\x1c\xc6'),
        # Test with class key variable
        (tdes.encrypt, [b'hello there', None, b'\x01'*8, False], b'H\xe5\xbb\xe5f\xa3(\xdak\xb3\x85o\x84\x08\x89\xfe'),

        # Decryption tests
        (tdes.decrypt, [b'\xd0m\x9b\xednX\x8e\x08\xb4\xbfj4\x1e\xbd\x1c\xc6', b'applejaminfosec8okyeahoh', b'\x01'*8], b'hello there'),
        # Test with class key variable
        (tdes.decrypt, [b'H\xe5\xbb\xe5f\xa3(\xdak\xb3\x85o\x84\x08\x89\xfe', None, b'\x01'*8], b'hello there')
    ]

    testsOFB = [
        # Encryption tests
        (des.encrypt, [b'hello there', b'infosec8', b'\x00'*8], b'2~\xc4\xa6(\xab\xf5\x081\xfa\xcc'),
    
        # Decryption tests
        (des.decrypt, [hw9.ciphertext3, hw9.secret_key3, hw9.initvector3],
         b'Therefore, since we are surrounded by such a huge crowd of witnesses to the life of faith, let us strip off every weight that slows us down, especially the sin that so easily trips us up. And let us run with endurance the race God has set before us. We do this by keeping our eyes on Jesus, the champion who initiates and perfects our faith. Because of the joy awaiting him, he endured the cross, disregarding its shame. Now he is seated in the place of honor beside GoD\x19s throne.'),

        # Triple DES Encryption tests
        (tdes.encrypt, [b'hello there', b'applejaminfosec8okyeahoh', b'\x01'*8], b'\x84.$c\xfb\x1b2\\\x06\xe7\xe5'),
        # Test with class key variable 
        (tdes.encrypt, [b'hello there', None, b'\x01'*8], b'\x89?\xc2\xc5#\x9f\x1f\x82\xb3<O'),

        # Decryption tests
        (tdes.decrypt, [b'\x84.$c\xfb\x1b2\\\x06\xe7\xe5', b'applejaminfosec8okyeahoh', b'\x01'*8], b'hello there'),
        # Test with class key variable
        (tdes.decrypt, [b'\x89?\xc2\xc5#\x9f\x1f\x82\xb3<O', None, b'\x01'*8], b'hello there'),

    ]

    des.mode = 'ECB'

    print(f'Running {len(testsECB)} ECB System tests...')
    for i, test in enumerate(testsECB):
        func = test[0]
        args = test[1]
        output = test[2]
        try:
            result = func(*args)
        except Exception as e:
            print(f"Error on test #{i} {func.__name__}() {args}")
            raise e


        assert result == output, f"❌ System test #{i+1} failed: {func.__name__}({args})\ngot {result} != {output}"    

    des.mode = 'CBC'
    tdes.mode = 'CBC'

    print(f'Running {len(testsCBC)} CBC System tests...')
    for i, test in enumerate(testsCBC):
        func = test[0]
        args = test[1]
        output = test[2]

        result = func(*args)
        assert result == output, f"❌ System test #{i+1} failed: {func.__name__}({args})\ngot {result} != {output}"      

    des.mode = 'OFB'
    tdes.mode = 'OFB'
    print(f'Running {len(testsOFB)} OFB System tests...')
    for i, test in enumerate(testsOFB):
        func = test[0]
        args = test[1]
        output = test[2]

        result = func(*args)
        assert result == output, f"❌ System test #{i+1} failed: {func.__name__}({args})\ngot {result} != {output}"    


    print('All SYSTEM TESTS PASSED ✅')



if __name__ == '__main__':
    # Test stuff
    des = cui_des.DES(mode='ECB', key=b'applejam')
    tdes = cui_des.T_DES(mode='ECB', key=b'anappleadaykeepsthedocto')
    run_unit_tests(des)
    print()
    run_system_tests(des, tdes)
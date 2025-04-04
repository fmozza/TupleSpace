# setup.py
from setuptools import setup, Extension
from Cython.Build import cythonize

extensions = [
    Extension(
        "test_client",
        ["test_client.pyx", "tuple_encrypt.c", "tuple.c", "tuple_utils.c"],  # Add tuple_utils.c
        libraries=["crypto", "glib-2.0", "pthread"],
        extra_compile_args=["-g"],
        extra_link_args=["-g"],
        include_dirs=["."]
    )
]

setup(
    ext_modules=cythonize(
        extensions,
        compiler_directives={'language_level': "3"}
    ),
)
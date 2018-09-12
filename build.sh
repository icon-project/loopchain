#!/bin/bash

PYVER=$(python -c 'import sys; print(sys.version_info[0])')
if [[ PYVER -ne 3 ]];then
  echo "The script should be run on python3"
  exit 1
fi

pip install -r requirements.txt
pip install wheel
rm -rf build dist/*.whl *.egg-info

mv loopchain/configure_user.py configure_user.py
python setup.py bdist_wheel
rm -rf build *.egg-info
mv configure_user.py loopchain/configure_user.py


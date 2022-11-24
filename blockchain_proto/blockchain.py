from argparse import ArgumentParser
import hashlib
import json
import os
from time import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from uuid import uuid4

from ecdsa import SigningKey


import requests
from flask import Flask, jsonify, request, send_from_directory
# from tracecms import trace_cms

class InputScript:
    def __init__(self, Sigiture, PublicKey):
        # type P2PKH
        self.sigiture = Sigiture
        self.pk = PublicKey


class OutputScript:
    def __init__(self, PublicKeyHash):
        # type P2PKH
        self.PublicKeyHash = PublicKeyHash

class Blockchain:
    def __init__(self):
        self.current_records = []
        self.chain = []
        self.length = 0
        self.nodes = set()
        self.mine_flag = False
        self.chain_file = 'data.json'
        self.node_file = 'nodes.json'
        

        try:
            with open(filepath + self.chain_file, 'r') as f:
                data = json.load(f)
                self.chain = data['chain']
                self.length = data['length']
        except:
            # 创建创世块
            self.new_block(proof=1, previous_hash='1', miner=node_identifier)

        try:
            with open(filepath + self.node_file, 'r') as f:
                data = json.load(f)
                self.nodes = set(data['nodes'])
        except:
            pass

    def register_node(self, address: str) -> None:
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def valid_chain(self, chain: List[Dict[str, Any]]) -> bool:
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            if block['previous_hash'] != self.hash(last_block):
                return False

            last_block = block
            current_index += 1

        return True

    def valid_block(self, block) -> bool:
        last_block = self.chain[-1]
        if block['previous_hash'] != self.hash(last_block):
            return False
        if (hash(block)[:5] != '00000'):
            return False
        return True

    def resolve_conflicts(self) -> bool:
        neighbours = self.nodes
        new_chain = None

        # 最长链的长度为max_length
        max_length = self.length

        # 获取并验证区块链网络中所有节点的链
        for node in app.config['nodes']:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # 若长度更长并且通过验证，更新max_length和new_chain
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # 若发现更长的链，用该链将自己的链替换掉
        if new_chain:
            self.chain = new_chain
            self.length = max_length
            return True

        return False

    def new_block(self, proof: int, previous_hash: str, miner) -> Dict[str, Any]:
        index = len(self.chain) + 1
        timestamp = time()
        records = self.current_records
        prev_hash = previous_hash or self.hash(self.chain[-1])
        block_string = str(index)+str(timestamp) + \
            str(''.join(str(records)))+str(prev_hash)

        # find good nonce
        hash1 = hashlib.sha256(block_string.encode('utf-8')).hexdigest()
        while True:
            hash2 = hashlib.sha256(
                (str(proof)+str(hash1)).encode('utf-8')).hexdigest()
            if (str(hash2)[:5] == '00000'):
                break
            proof += 1

        block = {
            'index': index,
            'timestamp': timestamp,
            'records': records,
            'proof': proof,
            'previous_hash': prev_hash,
            'miner': miner,
        }

        # clear records after it's written on block
        self.current_records = []

        # 将新块加入区块链
        self.chain.append(block)
        self.length += 1

        # 修改data文件
        f = open(filepath + self.chain_file, 'w')
        f.write(json.dumps({
            'chain': self.chain,
            'length': self.length,
        }))
        f.close()

        return block

    def new_record(self, id: str, maker: str, maker_sign: str, logistics: str, logistics_sign: str, receiver: str, receiver_sign: str, previous_hash, stamp,path) -> int:
        route = []
        # if request from maker
        if (maker != ''):
            # open maker.json
            sign_file = 'maker.json'
            with open(filepath + sign_file, 'r') as f:
                data = json.load(f)
            #create signature for maker
            pr_obj = SigningKey.from_pem(bytes.fromhex(data[maker]))
            maker_sign = pr_obj.sign(b'dawg').hex()
            #if already exist, return error
            for b in self.chain:
                for record in b['records']:
                    if(record['id'] == id):
                        return False
            route.append(path)

        if (logistics != ''):
            sign_file = 'logistics.json'
            with open(filepath + sign_file, 'r') as f:
                data = json.load(f)
            #create sign for logistics
            pr_obj = SigningKey.from_pem(bytes.fromhex(data[logistics]))
            logistics_sign = pr_obj.sign(b'dawg').hex()
            # find maker and maker sign
            for b in self.chain:
                for record in b['records']:
                    if(record['id'] == id):
                        #if logistics already exist, return error
                        if(record['logistics'] != ''):
                            return False
                        maker = record['maker']
                        maker_sign = record['maker sign']
                        route = record['path']
            route.append(path)
            previous_hash = hashlib.sha256(
                (str(maker)+str(maker_sign)).encode('utf-8')).hexdigest()

        if (receiver != ''):
            sign_file = 'receiver.json'
            with open(filepath + sign_file, 'r') as f:
                data = json.load(f)
            #create sign for receiver
            pr_obj = SigningKey.from_pem(bytes.fromhex(data[receiver]))
            receiver_sign = pr_obj.sign(b'dawg').hex()
            for b in self.chain:
                for record in b['records']:
                    if(record['id'] == id):
                        #if logistics already exist, return error
                        if(record['receiver'] != ''):
                            return False
                        maker = record['maker']
                        maker_sign = record['maker sign']
                        logistics = record['logistics']
                        logistics_sign = record['logistics sign']
                        route = record['path']
            route.append(path)
            previous_hash = hashlib.sha256(
                (str(maker)+str(maker_sign)+str(logistics)+str(logistics_sign)).encode('utf-8')).hexdigest()

        record = {
            'id': id,
            'maker': maker,
            'maker sign': maker_sign,
            'logistics': logistics,
            'logistics sign': logistics_sign,
            'receiver': receiver,
            'receiver sign': receiver_sign,
            'previous hash': previous_hash,
            'timestamp': stamp,
            'path':route
        }
        self.current_records.append(record)

        return record

    @staticmethod
    def hash(block: Dict[str, Any]) -> str:
        index = block['index']
        timestamp = block['timestamp']
        records = block['records']
        prev_hash = block['previous_hash']
        proof = block['proof']
        block_string = str(index)+str(timestamp) + \
            str(''.join(str(records)))+str(prev_hash)
        # find good nonce
        hash1 = hashlib.sha256(block_string.encode('utf-8')).hexdigest()
        hash2 = hashlib.sha256(
            (str(proof)+str(hash1)).encode('utf-8')).hexdigest()
        return str(hash2)

    def add_block(self, block):
        self.chain.append(block)
        self.length += 1

        # 新加，其余节点添加区块时，要把本地已经被打包进区块的record删掉
        for record in block['records']:
            if record['id'] == self.current_records['id']:
                self.current_records.remove(record)

        # 修改data文件
        f = open(filepath + self.chain_file, 'w')
        f.write(json.dumps({
            'chain': self.chain,
            'length': self.length,
        }))
        f.close()

# 实例化节点
app = Flask(__name__)

ip_prefix = '0.0.0.0:'

parser = ArgumentParser()
parser.add_argument('-p', '--port', default=5000,
                    type=int, help='port to listen on')
args = parser.parse_args()
port = args.port

app.config['port'] = args.port

# node存储形式 0.0.0.0:port
app.config['nodes'] = [ip_prefix+str(args.port)]


filepath = './data/'
info_file = 'info.json'
pdf_path = os.path.join(filepath, 'records')

if not os.path.exists(filepath):
    os.makedirs(filepath)
    os.makedirs(pdf_path)

try:
    # 取出节点地址
    with open(filepath + info_file, 'r') as file:
        node_identifier = json.load(file)['id']
except:
    # 若不存在，为此节点生成全局唯一地址
    node_identifier = str(uuid4()).replace('-', '')
    file = open(filepath + info_file, 'w')
    file.write(json.dumps({
        'id': node_identifier
    }))
    file.close()

# 实例化区块链
blockchain = Blockchain()

# 网络请求header
headers = {'content-type': 'application/json'}


def send_requests(path, data, fiter_host=None):
    for node in app.config['nodes'][:]:
        if node == ip_prefix+str(app.config['port']) or fiter_host == node:
            continue
        # url = 'http://0.0.0.0:%s%s' % (node, path)
        url = 'http://%s%s' % (node, path)
        try:
            # header added here as we run all nodes on one domain and need somehow understand the sender node
            # to not create broadcast loop
            requests.post(url, json=data, timeout=2, headers=headers)
        except:
            pass


@app.route('/mine', methods=['GET', 'POST'])
def mine():
    # 挖矿接口
    last_block = blockchain.chain[-1]
    proof = last_block['proof']+1

    # 生成新区块
    block = blockchain.new_block(proof, None, node_identifier)

    # TODO
    send_requests("/broadcast_block", json.dumps(block))

    response = {
        'index': block['index'],
        'timestamp': block['timestamp'],
        'records': block['records'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
        'miner': block['miner'],
    }

    return jsonify(response), 200

# @app.route('/stop_mine', methods=['GET', 'POST'])
# def stop_mine():
#     blockchain.mine_flag = False
#     return jsonify({"result": "Success"}), 201

@app.route('/broadcast_block', methods=['GET', 'POST'])
def broadcast_block():
    #check if current chain is correct
    consensus()
    values = request.get_json()
    required = ['index', 'timestamp', 'records',
                'proof', 'previous_hash', 'miner']
    if not all(k in values for k in required):
        response = {
            'message': 'missing values',
        }
        return jsonify(response), 400

    if blockchain.valid_block(block=json.loads(values)):
        blockchain.add_block(block=json.loads(values))
        response = {
            'message': 'adding block successfully',
        }
        #update consensus just in case
        consensus()
        return jsonify(response), 201
    response = {
        'message': 'adding block failed',
    }
    return jsonify(response), 400


@app.route('/new_maker', methods=['GET', 'POST'])
def new_maker():
    values = request.get_json()

    # 检查POST数据
    required = ['id', 'maker']
    if not all(k in values for k in required):
        response = {
            'message': 'missing values',
            'record_pool':blockchain.current_records
        }
        return jsonify(response), 400

    # 添加一个新的报告信息
    # TODO
    record = blockchain.new_record(id=values['id'],
                                   maker=values['maker'],
                                   maker_sign='',
                                   logistics='',
                                   logistics_sign='',
                                   receiver='',
                                   receiver_sign='',
                                   previous_hash='',
                                   stamp=time(),
                                   path= values['path']
                                   )

    print(record)
    send_requests("/broadcast_maker", json.dumps(record))
    response = {
        'message': 'add new transaction success',
        'record_pool':blockchain.current_records
    }
    return jsonify(response), 201


@app.route('/broadcast_maker', methods=['GET', 'POST'])
def broadcast_maker():
    """
    添加新数据接口
    :return:
    """
    values = request.get_json()
    required = ['id', 'maker']
    if not all(k in values for k in required):
        response = {
            'message': 'missing values',
        }
        return jsonify(response), 400

    blockchain.new_record(id=values['id'],
                          maker=values['maker'],
                          maker_sign=values['maker sign'],
                          logistics=values['logistics'],
                          logistics_sign=values['logistics sign'],
                          receiver=values['receiver'],
                          receiver_sign=values['receiver sign'],
                          previous_hash=values['previous hash'],
                          stamp=values['timestamp'],
                          path= values['path']
                          )

    return jsonify(response), 201


@app.route('/new_logistics', methods=['GET', 'POST'])
def new_logistics():
    """
    添加新数据接口
    :return:
    """
    values = request.get_json()

    # 检查POST数据
    required = ['id', 'logistics']
    if not all(k in values for k in required):
        response = {
            'message': 'missing values',
            'record_pool':blockchain.current_records
        }
        return jsonify(response), 400

    # 添加一个新的报告信息
    # TODO
    record = blockchain.new_record(id=values['id'],
                                   maker='',
                                   maker_sign='',
                                   logistics=values['logistics'],
                                   logistics_sign='',
                                   receiver='',
                                   receiver_sign='',
                                   previous_hash='',
                                   stamp=time(),
                                   path= values['path']
                                   )

    send_requests("/broadcast_logistics", data=json.dumps(record))
    response = {
        'message': 'add new transaction success',
        'record_pool':blockchain.current_records
    }
    return jsonify(response), 201


@app.route('/broadcast_logistics', methods=['GET', 'POST'])
def broadcast_logistics():
    """
    添加新数据接口
    :return:
    """
    values = request.get_json()
    required = ['id', 'logistics']
    if not all(k in values for k in required):
        response = {
            'message': 'missing values',
        }
        return jsonify(response), 400

    blockchain.new_record(id=values['id'],
                          maker=values['maker'],
                          maker_sign=values['maker sign'],
                          logistics=values['logistics'],
                          logistics_sign=values['logistics sign'],
                          receiver=values['receiver'],
                          receiver_sign=values['receiver sign'],
                          previous_hash=values['previous hash'],
                          stamp=values['timestamp'],
                          path= values['path']
                          )

    return jsonify(response), 201


@app.route('/new_receiver', methods=['GET', 'POST'])
def new_receiver():
    """
    添加新数据接口
    :return:
    """
    values = request.get_json()

    # 检查POST数据
    required = ['id', 'receiver']
    if not all(k in values for k in required):
        response = {
            'message': 'missing values',
            'record_pool':blockchain.current_records
        }
        print(response)
        return jsonify(response), 400

    # 添加一个新的报告信息
    # TODO
    record = blockchain.new_record(id=values['id'],
                                   maker='',
                                   maker_sign='',
                                   logistics='',
                                   logistics_sign='',
                                   receiver=values['receiver'],
                                   receiver_sign='',
                                   previous_hash='',
                                   stamp=time(),
                                   path= values['path']
                                   )

    send_requests("/broadcast_receiver", data=json.dumps(record))
    response = {
        'message': 'add new transaction success',
        'record_pool':blockchain.current_records
    }
    print(response)
    return jsonify(response), 201


@app.route('/broadcast_receiver', methods=['GET', 'POST'])
def broadcast_receiver():
    """
    添加新数据接口
    :return:
    """
    values = request.get_json()
    required = ['id', 'receiver']
    if not all(k in values for k in required):
        response = {
            'message': 'missing values',
        }
        return jsonify(response), 400

    blockchain.new_record(id=values['id'],
                          maker=values['maker'],
                          maker_sign=values['maker sign'],
                          logistics=values['logistics'],
                          logistics_sign=values['logistics sign'],
                          receiver=values['receiver'],
                          receiver_sign=values['receiver sign'],
                          previous_hash=values['previous hash'],
                          stamp=values['timestamp'],
                          path= values['path']
                          )

    return jsonify(response), 201


@app.route('/chain', methods=['GET', 'POST'])
def full_chain():
    """
    查看整个区块链接口
    :return:
    """
    response = {
        'chain': blockchain.chain,
        'length': blockchain.length,
    }
    return jsonify(response), 200

# TODO 需要修改nodes
# 原本的node 192.168.1.1 我们的node 端口号


"""
{'nodes':["5000","5001",..."5010"]}
"""


@app.route('/sync_nodes', methods=['GET', 'POST'])
def sync_nodes():
    """
    节点注册接口
    :return:
    """
    if isinstance(request.get_json(), str):
        values = json.loads(request.get_json()).get('node')
    else:
        values = request.get_json().get('node')

    if values is None:
        return "Error: Please supply a valid list of nodes", 400
    if not isinstance(values, str):
        values = str(values)

    url = 'http://0.0.0.0:%s%s' % (values, '/get_nodes')
    response = requests.post(url, timeout=2, headers=headers)
    response = response.json()

    for node in response['nodes']:
        blockchain.register_node('http://'+node)
        if not isinstance(node, str):
            node = str(node)
        if node not in app.config['nodes']:
            app.config['nodes'].append(node)
            send_requests(
                '/sync_nodes',
                data=json.dumps({'node': str(app.config['port'])})
            )

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201


@app.route('/consensus', methods=['GET', 'POST'])
def consensus():
    """
    解决冲突接口
    :return:
    """
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200


@app.route('/get_tx_pool', methods=['GET', 'POST'])
def get_tx_pool():
    """
    添加新数据接口
    :return:
    """

    response = {
        'records': blockchain.current_records,
        'length': len(blockchain.current_records)
    }
    return jsonify(response), 201


@app.route('/get_nodes', methods=['GET', 'POST'])
def get_nodes():
    """
    添加新数据接口
    :return:
    """

    response = {
        'nodes': app.config['nodes'],
        'length': len(app.config['nodes'])
    }
    return jsonify(response), 201


"""
{'id':xxx}
"""


@app.route('/query_record', methods=['GET', 'POST'])
def query_record():
    ID = request.args.get('id')
    records = []
    total = 0
    if ID:
        for block in blockchain.chain:
            for report in block['records']:
                if report['name'] == ID:
                    # 拷贝给data，使得data添加元素不影响blockchain.chain
                    data = report.copy()
                    data['block'] = block['index']
                    records.append(data)
                    total += 1
    else:
        for block in blockchain.chain:
            for report in block['records']:
                # 拷贝给data，使得data添加元素不影响blockchain.chain
                data = report.copy()
                data['block'] = block['index']
                records.append(data)
                total += 1
    records.reverse()
    response = {
        'records': records,
        'length': len(records)
    }
    return jsonify(response), 200


"""
{'index':xxx}
"""
@app.route('/stop_mine', methods=['GET', 'POST'])
def stop_mine():
    blockchain.mine_flag = False
    return jsonify({"result": "Success"}), 201

@app.route('/query_block', methods=['GET', 'POST'])
def query_block():
    index = int(request.get_json().get('index'))
    if index > blockchain.length:
        index = 0
    return jsonify(blockchain.chain[index-1]), 200


if __name__ == '__main__':
    port = 5000
    app.run(host='127.0.0.1', port=port)

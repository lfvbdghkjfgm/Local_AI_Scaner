#!/usr/bin/env python3
import sys
import json
import argparse
import traceback
import warnings
warnings.filterwarnings('ignore', message='In the future `np.object` will be defined', category=FutureWarning)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--type', required=True)
    parser.add_argument('--path', required=True)
    args = parser.parse_args()
    t = args.type
    p = args.path

    try:
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (10, 20))
            resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
        except Exception:
            pass

        try:
            import socket
            class _BlockedSocket:
                def __init__(self, *a, **k):
                    raise RuntimeError('Network operations disabled in safe_loader')
            socket.socket = _BlockedSocket
        except Exception:
            pass

        if t == 'pytorch':
            import torch
            import numpy as _np
            data = torch.load(p, map_location='cpu')
            if isinstance(data, dict):
                keys = list(data.keys())[:200]
                tensor_stats = {}
                for k in keys[:10]:
                    v = data.get(k)
                    try:
                        if hasattr(v, 'cpu'):
                            arr = v.cpu().numpy()
                        else:
                            continue
                        flat = arr.flatten()
                        size = int(flat.size)
                        if size > 0:
                            abs_flat = _np.abs(flat)
                            extreme_threshold = float(_np.percentile(abs_flat, 99.9))
                            extreme_count = int(_np.sum(abs_flat > extreme_threshold))
                            unique_ratio = float(len(_np.unique(flat)) / float(size))
                        else:
                            extreme_count = 0
                            unique_ratio = 1.0
                        tensor_stats[k] = {
                            'shape': list(arr.shape),
                            'size': size,
                            'extreme_count': int(extreme_count),
                            'unique_ratio': float(unique_ratio)
                        }
                    except Exception:
                        continue
                out = {'is_state_dict': True, 'keys': keys, 'tensor_stats': tensor_stats}
                print(json.dumps(out))
                return
            else:
                print(json.dumps({'is_state_dict': False, 'model_type': str(type(data))}))
                return

        if t == 'keras':
            import tensorflow as tf
            model = tf.keras.models.load_model(p, compile=False)
            layers = []
            for layer in model.layers:
                try:
                    cfg = layer.get_config()
                except Exception:
                    cfg = {}
                weights = []
                try:
                    for w in layer.get_weights():
                        weights.append({'shape': list(w.shape)})
                except Exception:
                    weights = []
                layers.append({'name': getattr(layer, 'name', ''), 'type': type(layer).__name__, 'config': cfg, 'weights': weights})
            print(json.dumps({'layers': layers}))
            return

        print(json.dumps({'error': 'unsupported_type'}))

    except Exception as e:
        tb = traceback.format_exc()
        sys.stdout.write(json.dumps({'error': str(e), 'trace': tb}))
        sys.exit(2)

if __name__ == '__main__':
    main()

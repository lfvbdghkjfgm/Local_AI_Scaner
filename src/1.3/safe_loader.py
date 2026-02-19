#!/usr/bin/env python3
import sys
import json
import argparse
import traceback
import warnings
warnings.filterwarnings('ignore', message='In the future `np.object` will be defined', category=FutureWarning)

def _compute_weight_stats(arr):
    """Compute comprehensive statistical metrics for weight anomaly detection"""
    try:
        flat = arr.flatten()
        if flat.size == 0:
            return {}
        
        import numpy as np
        from scipy.stats import entropy
        
        mean = float(np.mean(flat))
        std = float(np.std(flat))
        median = float(np.median(flat))
        

        if std > 1e-6:
            m4 = float(np.mean((flat - mean) ** 4))
            m2 = float(np.mean((flat - mean) ** 2))
            kurtosis = m4 / (m2 ** 2) - 3  # excess kurtosis
        else:
            kurtosis = 0.0
        

        if std > 1e-6:
            m3 = float(np.mean((flat - mean) ** 3))
            skewness = m3 / (std ** 3)
        else:
            skewness = 0.0
        

        l2_norm = float(np.linalg.norm(flat))
        


        hist, _ = np.histogram(flat, bins=min(256, flat.size // 10 + 1))
        hist = hist[hist > 0]
        if len(hist) > 0:
            weight_entropy = float(entropy(hist))
        else:
            weight_entropy = 0.0
        

        sparsity = float(np.sum(np.abs(flat) < 1e-6) / float(flat.size))
        

        percentile_25 = float(np.percentile(np.abs(flat), 25))
        percentile_75 = float(np.percentile(np.abs(flat), 75))
        iqr = percentile_75 - percentile_25
        
        return {
            'mean': mean,
            'median': median,
            'std': std,
            'kurtosis': kurtosis,
            'skewness': skewness,
            'min': float(np.min(flat)),
            'max': float(np.max(flat)),
            'l2_norm': l2_norm,
            'entropy': weight_entropy,
            'sparsity': sparsity,
            'iqr': iqr,
            'percentile_25': percentile_25,
            'percentile_75': percentile_75
        }
    except Exception:
        return {}

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
                keys = list(data.keys())
                tensor_stats = {}

                for k in keys:
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
                        

                        weight_stats = _compute_weight_stats(arr)
                        

                        param_type = 'bias' if 'bias' in k.lower() else 'weight'
                        
                        tensor_stats[k] = {
                            'shape': list(arr.shape),
                            'size': size,
                            'param_type': param_type,
                            'extreme_count': int(extreme_count),
                            'unique_ratio': float(unique_ratio),
                            'kurtosis': weight_stats.get('kurtosis', 0.0),
                            'skewness': weight_stats.get('skewness', 0.0),
                            'mean': weight_stats.get('mean', 0.0),
                            'median': weight_stats.get('median', 0.0),
                            'std': weight_stats.get('std', 0.0),
                            'l2_norm': weight_stats.get('l2_norm', 0.0),
                            'entropy': weight_stats.get('entropy', 0.0),
                            'sparsity': weight_stats.get('sparsity', 0.0),
                            'iqr': weight_stats.get('iqr', 0.0)
                        }
                    except Exception:
                        continue
                out = {'is_state_dict': True, 'keys': keys, 'total_tensors': len(keys), 'tensor_stats': tensor_stats}
                print(json.dumps(out))
                return
            else:
                print(json.dumps({'is_state_dict': False, 'model_type': str(type(data))}))
                return

        if t == 'keras':
            import tensorflow as tf
            import numpy as _np
            model = tf.keras.models.load_model(p, compile=False)
            layers = []

            for layer in model.layers:
                try:
                    cfg = layer.get_config()
                except Exception:
                    cfg = {}
                weights = []
                try:
                    layer_weights = layer.get_weights()
                    has_bias = len(layer_weights) > 1
                    
                    for idx, w in enumerate(layer_weights):
                        w_stats = _compute_weight_stats(w)

                        weight_type = 'bias' if (idx == len(layer_weights) - 1 and has_bias) else 'weight'
                        weights.append({
                            'shape': list(w.shape),
                            'type': weight_type,
                            'size': int(w.size),
                            'stats': w_stats
                        })
                except Exception:
                    weights = []
                layers.append({
                    'name': getattr(layer, 'name', ''),
                    'type': type(layer).__name__,
                    'config': cfg,
                    'weights': weights
                })
            print(json.dumps({'layers': layers, 'total_layers': len(layers)}))
            return

        print(json.dumps({'error': 'unsupported_type'}))

    except Exception as e:
        tb = traceback.format_exc()
        sys.stdout.write(json.dumps({'error': str(e), 'trace': tb}))
        sys.exit(2)

if __name__ == '__main__':
    main()

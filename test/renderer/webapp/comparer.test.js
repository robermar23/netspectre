/**
 * comparer.test.js
 * Tests for the Myers O(ND) diff algorithm exported from comparer.js.
 * DOM-dependent init() is not tested here (requires jsdom setup).
 */

import { describe, it, expect } from 'vitest';
import { myersDiff } from '../../../src/renderer/modules/webapp/comparer.js';

// ─── myersDiff — basic cases ──────────────────────────────────────────────────

describe('myersDiff — empty inputs', () => {
  it('returns empty array for two empty sequences', () => {
    expect(myersDiff([], [])).toEqual([]);
  });

  it('returns all inserts when A is empty', () => {
    const result = myersDiff([], ['x', 'y']);
    expect(result.every(op => op.type === 'insert')).toBe(true);
    expect(result.map(op => op.value)).toEqual(['x', 'y']);
  });

  it('returns all deletes when B is empty', () => {
    const result = myersDiff(['a', 'b'], []);
    expect(result.every(op => op.type === 'delete')).toBe(true);
    expect(result.map(op => op.value)).toEqual(['a', 'b']);
  });
});

describe('myersDiff — identical sequences', () => {
  it('returns all-equal ops for identical arrays', () => {
    const seq    = ['foo', 'bar', 'baz'];
    const result = myersDiff(seq, seq);
    expect(result.every(op => op.type === 'equal')).toBe(true);
    expect(result.map(op => op.value)).toEqual(seq);
  });

  it('single element — equal', () => {
    const result = myersDiff(['hello'], ['hello']);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({ type: 'equal', value: 'hello' });
  });
});

describe('myersDiff — single-element differences', () => {
  it('detects one substitution as delete + insert', () => {
    const result = myersDiff(['a'], ['b']);
    const types = result.map(op => op.type).sort();
    expect(types).toEqual(['delete', 'insert']);
  });

  it('detects one insertion in the middle', () => {
    const result = myersDiff(['a', 'c'], ['a', 'b', 'c']);
    const inserted = result.filter(op => op.type === 'insert');
    expect(inserted).toHaveLength(1);
    expect(inserted[0].value).toBe('b');
  });

  it('detects one deletion in the middle', () => {
    const result = myersDiff(['a', 'b', 'c'], ['a', 'c']);
    const deleted = result.filter(op => op.type === 'delete');
    expect(deleted).toHaveLength(1);
    expect(deleted[0].value).toBe('b');
  });
});

describe('myersDiff — multi-element diffs', () => {
  it('handles prefix equal + tail diff', () => {
    const a = ['line1', 'line2', 'line3'];
    const b = ['line1', 'line2', 'lineX'];
    const result = myersDiff(a, b);

    const equalOps   = result.filter(op => op.type === 'equal');
    const deleteOps  = result.filter(op => op.type === 'delete');
    const insertOps  = result.filter(op => op.type === 'insert');

    expect(equalOps.map(op => op.value)).toContain('line1');
    expect(equalOps.map(op => op.value)).toContain('line2');
    expect(deleteOps.map(op => op.value)).toContain('line3');
    expect(insertOps.map(op => op.value)).toContain('lineX');
  });

  it('handles suffix equal + head diff', () => {
    const a = ['old', 'common1', 'common2'];
    const b = ['new1', 'new2', 'common1', 'common2'];
    const result = myersDiff(a, b);

    const equalValues  = result.filter(op => op.type === 'equal').map(op => op.value);
    const insertValues = result.filter(op => op.type === 'insert').map(op => op.value);
    const deleteValues = result.filter(op => op.type === 'delete').map(op => op.value);

    expect(equalValues).toContain('common1');
    expect(equalValues).toContain('common2');
    expect(deleteValues).toContain('old');
    expect(insertValues).toContain('new1');
    expect(insertValues).toContain('new2');
  });

  it('reconstructs B correctly from ops', () => {
    const a = ['apple', 'banana', 'cherry', 'date'];
    const b = ['apple', 'blueberry', 'cherry', 'elderberry'];
    const result = myersDiff(a, b);

    // Reconstruct B by applying ops
    const reconstructed = result
      .filter(op => op.type === 'equal' || op.type === 'insert')
      .map(op => op.value);

    expect(reconstructed).toEqual(b);
  });

  it('reconstructs A correctly from ops', () => {
    const a = ['x', 'y', 'z'];
    const b = ['x', 'w', 'z'];
    const result = myersDiff(a, b);

    const reconstructedA = result
      .filter(op => op.type === 'equal' || op.type === 'delete')
      .map(op => op.value);

    expect(reconstructedA).toEqual(a);
  });
});

describe('myersDiff — complete replacement', () => {
  it('everything replaced produces no equal ops', () => {
    const a = ['a', 'b', 'c'];
    const b = ['x', 'y', 'z'];
    const result = myersDiff(a, b);

    expect(result.some(op => op.type === 'equal')).toBe(false);
    expect(result.filter(op => op.type === 'delete').map(op => op.value)).toEqual(['a', 'b', 'c']);
    expect(result.filter(op => op.type === 'insert').map(op => op.value)).toEqual(['x', 'y', 'z']);
  });
});

describe('myersDiff — longer sequences', () => {
  it('handles 20-element sequences with scattered changes', () => {
    const a = Array.from({ length: 20 }, (_, i) => `line${i}`);
    const b = [...a];
    b[5]  = 'changed-5';
    b[15] = 'changed-15';

    const result = myersDiff(a, b);

    // Equal ops should be the majority
    const equalCount = result.filter(op => op.type === 'equal').length;
    expect(equalCount).toBeGreaterThan(10);

    // Reconstructed B should match
    const reconstructed = result
      .filter(op => op.type !== 'delete')
      .map(op => op.value);
    expect(reconstructed).toEqual(b);
  });

  it('handles 50-element identical sequences efficiently', () => {
    const seq = Array.from({ length: 50 }, (_, i) => `item-${i}`);
    const result = myersDiff(seq, seq);

    expect(result).toHaveLength(50);
    expect(result.every(op => op.type === 'equal')).toBe(true);
  });

  it('handles append-only diff (B extends A)', () => {
    const a = ['a', 'b', 'c'];
    const b = ['a', 'b', 'c', 'd', 'e'];
    const result = myersDiff(a, b);

    const insertedValues = result.filter(op => op.type === 'insert').map(op => op.value);
    expect(insertedValues).toEqual(['d', 'e']);

    const deletedCount = result.filter(op => op.type === 'delete').length;
    expect(deletedCount).toBe(0);
  });

  it('handles prepend-only diff (B extends before A)', () => {
    const a = ['c', 'd', 'e'];
    const b = ['a', 'b', 'c', 'd', 'e'];
    const result = myersDiff(a, b);

    const insertedValues = result.filter(op => op.type === 'insert').map(op => op.value);
    expect(insertedValues).toContain('a');
    expect(insertedValues).toContain('b');

    const deletedCount = result.filter(op => op.type === 'delete').length;
    expect(deletedCount).toBe(0);
  });
});

describe('myersDiff — operation types', () => {
  it('every operation has type and value fields', () => {
    const result = myersDiff(['a', 'b'], ['b', 'c']);
    for (const op of result) {
      expect(op).toHaveProperty('type');
      expect(op).toHaveProperty('value');
      expect(['equal', 'insert', 'delete']).toContain(op.type);
    }
  });

  it('no operations have undefined value', () => {
    const result = myersDiff(['hello world'], ['hello there']);
    for (const op of result) {
      expect(op.value).toBeDefined();
    }
  });
});

describe('myersDiff — string content with special chars', () => {
  it('handles strings with HTML special characters as values', () => {
    const a = ['<div>', '</div>'];
    const b = ['<span>', '</span>'];
    const result = myersDiff(a, b);

    // Should not throw and should produce valid ops
    expect(result.length).toBeGreaterThan(0);
  });

  it('handles empty string tokens', () => {
    const a = ['a', '', 'b'];
    const b = ['a', '', 'c'];
    const result = myersDiff(a, b);

    const reconstructed = result
      .filter(op => op.type !== 'delete')
      .map(op => op.value);
    expect(reconstructed).toEqual(b);
  });
});

describe('myersDiff — real-world HTTP request diff', () => {
  it('diffs two similar HTTP requests correctly', () => {
    const reqA = [
      'GET /login HTTP/1.1',
      'Host: example.com',
      'Cookie: session=abc123',
      '',
      '',
    ];
    const reqB = [
      'POST /login HTTP/1.1',
      'Host: example.com',
      'Cookie: session=abc123',
      'Content-Type: application/json',
      '',
    ];

    const result = myersDiff(reqA, reqB);

    // Host and Cookie lines should be equal
    const equalLines = result.filter(op => op.type === 'equal').map(op => op.value);
    expect(equalLines).toContain('Host: example.com');
    expect(equalLines).toContain('Cookie: session=abc123');

    // First line changed: GET → POST
    const deletedLines = result.filter(op => op.type === 'delete').map(op => op.value);
    expect(deletedLines).toContain('GET /login HTTP/1.1');

    const insertedLines = result.filter(op => op.type === 'insert').map(op => op.value);
    expect(insertedLines).toContain('POST /login HTTP/1.1');
  });
});

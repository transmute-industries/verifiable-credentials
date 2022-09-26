/* eslint-disable max-len */
const fs = require('fs');

let counter = 0;

const getId = () => {
  counter++;
  return 'node_' + counter;
};

const traverse = (node) => {
  const nodeId = getId();
  const nodeType = Array.isArray(node) ? 'array' : typeof node;

  const nextNode = {
    id: nodeId,
    type: nodeType,
  };

  if (nodeType === 'object') {
    const children = [];
    for (const [key, value] of Object.entries(node)) {
      const visit = traverse(value);
      children.push(visit);
    }
    nextNode.children = children;
  }

  if (nodeType === 'array') {
    const children = [];
    for (const [key, value] of Object.entries(node)) {
      const visit = traverse(value);
      children.push(visit);
    }
    nextNode.children = children;
  }

  if (nodeType === 'string') {
    nextNode.value = node;
  }

  return nextNode;
};

const graphNodeToStatment = (gn) => {
  //   const links = gn.children
  //       .map((c) => {
  //         if (c.children.length) {
  //           return `
  // ${gn.id}[${gn.key}] --> ${c.id}
  //           `;
  //         } else {
  //           return `
  // ${gn.id}[${c.key}] --> ${c.id}[${c.value}]
  // `;
  //         }
  //       })
  //       .join('\n');
  //   return links + gn.children.map(graphNodeToStatment).join('\n');
};

const graphToDiagram = (graph) => {
  let statements = '';
  statements += graphNodeToStatment(graph);
  return `
\`\`\`mermaid
graph TD
${statements}
\`\`\`
`;
}

;(async () => {
  console.log('🧜‍♀️ ...');

  const intermediateGraph = traverse({
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      {
        '@vocab': 'https://brand.example/vocab#',
      },
    ],
    'type': ['VerifiableCredential'],
    'issuer': {
      id: 'did:example:123',
      type: 'Organization',
    },
    'issuanceDate': '2022-09-24T16:31:40.815Z',
    'credentialSubject': {
      id: 'did:example:456',
      type: 'Person',
    },
  });
  console.log(JSON.stringify(intermediateGraph, null, 2));

  const diagram = graphToDiagram(intermediateGraph);

  fs.writeFileSync('./experiments/credential-mermaids.md', diagram);
})();

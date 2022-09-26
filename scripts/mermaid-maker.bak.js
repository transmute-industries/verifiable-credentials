const fs = require('fs');

let counter = 0;
const objectToClass = (obj, edgeLabel) => {
  const classType = (obj.type || 'Object') + counter;
  counter++;

  //   if (Array.isArray(obj)) {
  //     const props = obj.map((item) => {
  //       return `  '${JSON.stringify(item)}'\n`;
  //     });
  //     const block = `
  // class ${classType} {
  //   <<Enumeration>>
  // ${props.join('\n')}
  // }
  // `;
  //     return {node: classType, edgeLabel, block, children: []};
  //   }

  let props = ``;
  const children = [];
  for (const [key, value] of Object.entries(obj)) {
    // console.log(key);
    // console.log(typeof value);
    if (typeof value === 'object') {
      children.push(objectToClass(value, key));
    } else {
      const propType = typeof value;
      props += `  ${propType} ${key}\n`;
    }
  }
  console.log(obj.type);

  const block = `
class ${classType} {
  <<Interface>>
${props}
}
`;

  return {node: classType, edgeLabel, block, children};
};

const graphNodeToStatment = (graphNode) => {
  if (graphNode.children.length === 0) {
    return graphNode.block;
  } else {
    const childBlocks = graphNode.children.map(graphNodeToStatment).join('\n');
    const links = graphNode.children
        .map((c) => {
          return `${graphNode.node} --> ${c.node}: ${c.edgeLabel}\n`;
        })
        .join('\n');
    return graphNode.block + links + '\n' + childBlocks;
  }
};

const graphToDiagram = (graph) => {
  let statements = '';
  statements += graphNodeToStatment(graph);
  return `
\`\`\`mermaid
classDiagram
${statements}
\`\`\`
`;
}

;(async () => {
  console.log('🧜‍♀️ ...');

  const intermediateGraph = objectToClass({
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

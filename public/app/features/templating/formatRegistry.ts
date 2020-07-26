import kbn from 'app/core/utils/kbn';
import { Registry, RegistryItem, VariableModel } from '@grafana/data';
import { map } from 'lodash';

export interface FormatRegistryItem extends RegistryItem {
  formatter(value: any, args: string[], variable: VariableModel): string;
}

export const formatRegistry = new Registry<FormatRegistryItem>(() => {
  const formats: FormatRegistryItem[] = [
    {
      id: 'lucene',
      name: 'Lucene',
      description: 'Values are lucene escaped and multi-valued variables generate an OR expression',
      formatter: value => {
        if (typeof value === 'string') {
          return luceneEscape(value);
        }

        if (value instanceof Array && value.length === 0) {
          return '__empty__';
        }

        const quotedValues = map(value, (val: string) => {
          return '"' + luceneEscape(val) + '"';
        });

        return '(' + quotedValues.join(' OR ') + ')';
      },
    },
    {
      id: 'regex',
      name: 'Regex',
      description: 'Values are regex escaped and multi-valued variables generate a (<value>|<value>) expression',
      formatter: value => {
        if (typeof value === 'string') {
          return kbn.regexEscape(value);
        }

        const escapedValues = map(value, kbn.regexEscape);
        if (escapedValues.length === 1) {
          return escapedValues[0];
        }
        return '(' + escapedValues.join('|') + ')';
      },
    },
    {
      id: 'pipe',
      name: 'Pipe',
      description: 'Values are seperated by | character',
      formatter: value => {
        if (typeof value === 'string') {
          return value;
        }
        return value.join('|');
      },
    },
    {
      id: 'distributed',
      name: 'Distributed',
      description: 'Multiple values are formatted like variable=value',
      formatter: (value, args, variable) => {
        if (typeof value === 'string') {
          return value;
        }

        value = map(value, (val: any, index: number) => {
          if (index !== 0) {
            return variable.name + '=' + val;
          } else {
            return val;
          }
        });
        return value.join(',');
      },
    },
  ];

  return formats;
});

function luceneEscape(value: string) {
  return value.replace(/([\!\*\+\-\=<>\s\&\|\(\)\[\]\{\}\^\~\?\:\\/"])/g, '\\$1');
}

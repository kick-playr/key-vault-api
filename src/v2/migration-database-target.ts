import {databaseNames} from './database-names.js';
import {scopeFilter} from './mongo-store.js';
import {databaseFromMongoUri} from '../mongodb-url.js';
import type {ResourceScope} from './records.js';
/** Reviewed namespace move only. Auth database, credential bytes and topology
 * remain exactly as supplied; this never creates/copies a database. */
export function rewriteReviewedDatabaseTarget(input:unknown,scope:ResourceScope,target:string):string {
 const owner=scopeFilter(scope),expected=owner.ownerType==='tenant'?databaseNames.tenant(owner.ownerId):databaseNames.control;
 if(target!==expected||typeof input!=='string')throw Error('Unapproved database target');
 databaseFromMongoUri(input);
 const match=input.match(/^(mongodb(?:\+srv)?:\/\/[^/?#]+)(?:\/[^?#]*)?(\?[^#]*)?$/);
 if(!match)throw Error('Invalid MongoDB connection configuration');
 return match[1]+'/'+encodeURIComponent(target)+(match[2]??'');
}

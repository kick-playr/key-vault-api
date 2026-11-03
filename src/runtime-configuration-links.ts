import type{Namespace}from'./types.js';import{fail}from'./errors.js';
/** A tenant publication becomes visible only after the shared commit selects it. */
export function materializeRuntimeLinks(ns:Namespace|undefined,publicationId:string|undefined):Namespace|undefined{
 if(!ns||!publicationId)return ns;const staged=ns.runtimeLinkPublications?.[publicationId];if(!staged)return ns;
 if(ns.generation!==staged.baseGeneration)fail(409,'RuntimeConfigurationConflict');
 ns.resourceAssociations=structuredClone(staged.associations);ns.applicationRevision=staged.applicationRevision;ns.generation=staged.baseGeneration+1;
 delete ns.runtimeLinkPublications![publicationId];
 if(ns.runtimePublicationReservation===publicationId)delete ns.runtimePublicationReservation;return ns;
}

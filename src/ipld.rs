//! Implementing the IPLD data model.

use std::collections::BTreeMap;
use std::convert::Infallible;

use bytes::Bytes;
use futures::Stream;
use typed_floats::NonNaNFinite;

use crate::cid::{Cidv1, CidRef, AnyCid};

trait List: Sized {
    type Elem: Repr;
    type Iter<'a>: Iterator<Item=&'a Node<Self::Elem>>
        where Self: 'a, Self::Elem: 'a;

    fn get(&self, x: usize) -> Option<&Node<Self::Elem>>;
    fn iter(&self) -> Self::Iter<'_>;
}

impl<R: Repr> List for Vec<Node<R>> {
    type Elem = R;
    type Iter<'a> = core::slice::Iter<'a, Node<R>>
        where Self: 'a, R: 'a;

    fn get(&self, x: usize) -> Option<&Node<R>> { self.as_slice().get(x) }
    fn iter(&self) -> Self::Iter<'_> { self.as_slice().iter() }
}

trait Map<R: Repr>: Sized {
    type Item: Repr;
    type Iter<'a>: Iterator<Item=(&'a R::String, &'a Node<Self::Item>)>
        where Self: 'a, R: 'a;

    fn get(&self, k: &R::String) -> Option<&Node<Self::Item>>;
    fn iter(&self) -> Self::Iter<'_>;
}

impl<R: Repr> Map<R> for BTreeMap<R::String, Node<R>> {
    type Item = R;
    type Iter<'a> = std::collections::btree_map::Iter<'a, R::String, Node<Self::Item>>
        where Self: 'a;

    fn get(&self, k: &R::String) -> Option<&Node<R>> {
        BTreeMap::get(self, k)
    }
    fn iter(&self) -> Self::Iter<'_> {
        BTreeMap::iter(self)
    }
}

struct Empty;
impl List for Empty {
    type Elem = Infallible;
    type Iter<'a> = std::iter::Empty<&'a Node<Infallible>>
        where Self: 'a, Infallible: 'a;
    
    fn get(&self, _: usize) -> Option<&Node<Infallible>> {
        None
    }

    fn iter(&self) -> Self::Iter<'_> {
        std::iter::empty()
    }
}

//-[ Async ]-//
trait AsyncList<R: AsyncRepr>: Sized {
    type Subrepr: Repr;
    type Iter<'a>: Stream<Item=&'a Node<Self::Subrepr>>
        where Self: 'a, R: 'a;

    async fn get(&self, x: usize) -> Option<&Node<R>>;
    fn iter(&self) -> Self::Iter<'_>;
}

trait AsyncMap<R: AsyncRepr>: Sized {
    type Subrepr: Repr;
    type Iter<'a>: Iterator<Item=(&'a R::String, &'a Node<Self::Subrepr>)>
        where Self: 'a, R: 'a;

    fn get(&self, k: &R::String) -> Option<&Node<Self::Subrepr>>;
    fn iter(&self) -> Self::Iter<'_>;
}

impl<R: Repr> Map<R> for BTreeMap<R::String, Node<R>> {
    type Item = R;
    type Iter<'a> = std::collections::btree_map::Iter<'a, R::String, Node<Self::Item>>
        where Self: 'a;

    fn get(&self, k: &R::String) -> Option<&Node<R>> {
        BTreeMap::get(self, k)
    }
    fn iter(&self) -> Self::Iter<'_> {
        BTreeMap::iter(self)
    }
}

struct Empty;
impl<R: Repr> List<R> for Empty {
    type Subrepr = R;
    type Iter<'a> = std::iter::Empty<&'a Node<R>>
        where Self: 'a, R: 'a;
    
    fn get(&self, _: usize) -> Option<&Node<R>> {
        None
    }

    fn iter(&self) -> Self::Iter<'_> {
        std::iter::empty()
    }
}

trait Repr {
    type String: Ord;
    type Bytes;
    type List: List<Self>;
    type Map: Map<Self>;
    type Link: CidRef;
}

pub enum Node<R: Repr> {
    Null,
    Boolean(bool),
    Integer(i128), // Support dag-cbor (u/s)int64
    Float(NonNaNFinite),
    String(R::String),

    Bytes(R::Bytes),
    List(R::List),
    Map(R::Map),
    Link(R::Link),
}

trait AsyncRepr {
    type String: Ord;
    type Bytes;
    type List: List<Self>;
    type Map: Map<Self>;
    type Link: CidRef;
}

struct CborRepr;
impl Repr for CborRepr {
    type String = String;
    type Bytes = Bytes;
    type Link = AnyCid<Bytes>;
    type Map = BTreeMap<String, Node<Self>>;
    type List = Vec<Node<Self>>;
}

type X = Node<&'static CborRepr>;
type Y = Node<CborRepr>;

use crate::dagpb::{self, UnixfsNode, PbLink};

enum DagPbMap {
    UnixfsNode(UnixfsNode),
    PbLink(PbLink),
    Data(dagpb::Data),
    UnixTime(dagpb::UnixTime),
}
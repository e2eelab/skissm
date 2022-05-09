// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: skissm/SenderChainNode.proto

#include "skissm/SenderChainNode.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG
namespace skissm {
constexpr SenderChainNode::SenderChainNode(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : ratchet_key_(&::PROTOBUF_NAMESPACE_ID::internal::fixed_address_empty_string)
  , chain_key_(nullptr){}
struct SenderChainNodeDefaultTypeInternal {
  constexpr SenderChainNodeDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~SenderChainNodeDefaultTypeInternal() {}
  union {
    SenderChainNode _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT SenderChainNodeDefaultTypeInternal _SenderChainNode_default_instance_;
}  // namespace skissm
static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_skissm_2fSenderChainNode_2eproto[1];
static constexpr ::PROTOBUF_NAMESPACE_ID::EnumDescriptor const** file_level_enum_descriptors_skissm_2fSenderChainNode_2eproto = nullptr;
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_skissm_2fSenderChainNode_2eproto = nullptr;

const uint32_t TableStruct_skissm_2fSenderChainNode_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::skissm::SenderChainNode, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  PROTOBUF_FIELD_OFFSET(::skissm::SenderChainNode, ratchet_key_),
  PROTOBUF_FIELD_OFFSET(::skissm::SenderChainNode, chain_key_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, -1, sizeof(::skissm::SenderChainNode)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::skissm::_SenderChainNode_default_instance_),
};

const char descriptor_table_protodef_skissm_2fSenderChainNode_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n\034skissm/SenderChainNode.proto\022\006skissm\032\025"
  "skissm/ChainKey.proto\"K\n\017SenderChainNode"
  "\022\023\n\013ratchet_key\030\001 \001(\014\022#\n\tchain_key\030\002 \001(\013"
  "2\020.skissm.ChainKeyB0\n\030org.e2eelab.skissm"
  ".protoB\024SenderChainNodeProtob\006proto3"
  ;
static const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable*const descriptor_table_skissm_2fSenderChainNode_2eproto_deps[1] = {
  &::descriptor_table_skissm_2fChainKey_2eproto,
};
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_skissm_2fSenderChainNode_2eproto_once;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_skissm_2fSenderChainNode_2eproto = {
  false, false, 196, descriptor_table_protodef_skissm_2fSenderChainNode_2eproto, "skissm/SenderChainNode.proto", 
  &descriptor_table_skissm_2fSenderChainNode_2eproto_once, descriptor_table_skissm_2fSenderChainNode_2eproto_deps, 1, 1,
  schemas, file_default_instances, TableStruct_skissm_2fSenderChainNode_2eproto::offsets,
  file_level_metadata_skissm_2fSenderChainNode_2eproto, file_level_enum_descriptors_skissm_2fSenderChainNode_2eproto, file_level_service_descriptors_skissm_2fSenderChainNode_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable* descriptor_table_skissm_2fSenderChainNode_2eproto_getter() {
  return &descriptor_table_skissm_2fSenderChainNode_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY static ::PROTOBUF_NAMESPACE_ID::internal::AddDescriptorsRunner dynamic_init_dummy_skissm_2fSenderChainNode_2eproto(&descriptor_table_skissm_2fSenderChainNode_2eproto);
namespace skissm {

// ===================================================================

class SenderChainNode::_Internal {
 public:
  static const ::skissm::ChainKey& chain_key(const SenderChainNode* msg);
};

const ::skissm::ChainKey&
SenderChainNode::_Internal::chain_key(const SenderChainNode* msg) {
  return *msg->chain_key_;
}
void SenderChainNode::clear_chain_key() {
  if (GetArenaForAllocation() == nullptr && chain_key_ != nullptr) {
    delete chain_key_;
  }
  chain_key_ = nullptr;
}
SenderChainNode::SenderChainNode(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor();
  if (!is_message_owned) {
    RegisterArenaDtor(arena);
  }
  // @@protoc_insertion_point(arena_constructor:skissm.SenderChainNode)
}
SenderChainNode::SenderChainNode(const SenderChainNode& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  ratchet_key_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    ratchet_key_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), "", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_ratchet_key().empty()) {
    ratchet_key_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, from._internal_ratchet_key(), 
      GetArenaForAllocation());
  }
  if (from._internal_has_chain_key()) {
    chain_key_ = new ::skissm::ChainKey(*from.chain_key_);
  } else {
    chain_key_ = nullptr;
  }
  // @@protoc_insertion_point(copy_constructor:skissm.SenderChainNode)
}

inline void SenderChainNode::SharedCtor() {
ratchet_key_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  ratchet_key_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), "", GetArenaForAllocation());
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
chain_key_ = nullptr;
}

SenderChainNode::~SenderChainNode() {
  // @@protoc_insertion_point(destructor:skissm.SenderChainNode)
  if (GetArenaForAllocation() != nullptr) return;
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

inline void SenderChainNode::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  ratchet_key_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (this != internal_default_instance()) delete chain_key_;
}

void SenderChainNode::ArenaDtor(void* object) {
  SenderChainNode* _this = reinterpret_cast< SenderChainNode* >(object);
  (void)_this;
}
void SenderChainNode::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void SenderChainNode::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void SenderChainNode::Clear() {
// @@protoc_insertion_point(message_clear_start:skissm.SenderChainNode)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  ratchet_key_.ClearToEmpty();
  if (GetArenaForAllocation() == nullptr && chain_key_ != nullptr) {
    delete chain_key_;
  }
  chain_key_ = nullptr;
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* SenderChainNode::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // bytes ratchet_key = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 10)) {
          auto str = _internal_mutable_ratchet_key();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // .skissm.ChainKey chain_key = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 18)) {
          ptr = ctx->ParseMessage(_internal_mutable_chain_key(), ptr);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* SenderChainNode::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:skissm.SenderChainNode)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // bytes ratchet_key = 1;
  if (!this->_internal_ratchet_key().empty()) {
    target = stream->WriteBytesMaybeAliased(
        1, this->_internal_ratchet_key(), target);
  }

  // .skissm.ChainKey chain_key = 2;
  if (this->_internal_has_chain_key()) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(
        2, _Internal::chain_key(this), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:skissm.SenderChainNode)
  return target;
}

size_t SenderChainNode::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:skissm.SenderChainNode)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // bytes ratchet_key = 1;
  if (!this->_internal_ratchet_key().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_ratchet_key());
  }

  // .skissm.ChainKey chain_key = 2;
  if (this->_internal_has_chain_key()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *chain_key_);
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData SenderChainNode::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSizeCheck,
    SenderChainNode::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*SenderChainNode::GetClassData() const { return &_class_data_; }

void SenderChainNode::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message* to,
                      const ::PROTOBUF_NAMESPACE_ID::Message& from) {
  static_cast<SenderChainNode *>(to)->MergeFrom(
      static_cast<const SenderChainNode &>(from));
}


void SenderChainNode::MergeFrom(const SenderChainNode& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:skissm.SenderChainNode)
  GOOGLE_DCHECK_NE(&from, this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_ratchet_key().empty()) {
    _internal_set_ratchet_key(from._internal_ratchet_key());
  }
  if (from._internal_has_chain_key()) {
    _internal_mutable_chain_key()->::skissm::ChainKey::MergeFrom(from._internal_chain_key());
  }
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void SenderChainNode::CopyFrom(const SenderChainNode& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:skissm.SenderChainNode)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool SenderChainNode::IsInitialized() const {
  return true;
}

void SenderChainNode::InternalSwap(SenderChainNode* other) {
  using std::swap;
  auto* lhs_arena = GetArenaForAllocation();
  auto* rhs_arena = other->GetArenaForAllocation();
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      &ratchet_key_, lhs_arena,
      &other->ratchet_key_, rhs_arena
  );
  swap(chain_key_, other->chain_key_);
}

::PROTOBUF_NAMESPACE_ID::Metadata SenderChainNode::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_skissm_2fSenderChainNode_2eproto_getter, &descriptor_table_skissm_2fSenderChainNode_2eproto_once,
      file_level_metadata_skissm_2fSenderChainNode_2eproto[0]);
}

// @@protoc_insertion_point(namespace_scope)
}  // namespace skissm
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::skissm::SenderChainNode* Arena::CreateMaybeMessage< ::skissm::SenderChainNode >(Arena* arena) {
  return Arena::CreateMessageInternal< ::skissm::SenderChainNode >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>